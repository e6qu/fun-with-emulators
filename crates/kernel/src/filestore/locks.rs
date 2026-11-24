//! File locks of the store's files: `flock`'s, and record locks (a
//! process's, `F_SETLK`, and an open file description's, `F_OFD_SETLK`).
//!
//! A file's locks are kept with it, in the filesystem's shared memory
//! ([`super::tree::Lock`]), so every process sees them: a `flock` lock and
//! an open file description's record lock are the description's (by its
//! id), and go when no process holds the description any more (its last
//! descriptor closed, or its holders ended); a process's record lock is
//! the process's, and goes when it closes any descriptor of the file or
//! ends ([`super::desc::sync`], [`super::desc::exiting`]). `flock` locks
//! and record locks are apart, as on Linux; a process's and a
//! description's record locks conflict.
//!
//! A lock that must wait sleeps on the filesystem's change word, which a
//! lock let go bumps and wakes ([`super::wait`]): it looks again on each
//! wake, ends with a signal for the thread (`EINTR`), and between wakes
//! forgets the holders that ended without letting go. A process's record
//! lock that would wait on a process waiting, through others, for it is
//! refused (`EDEADLK`): each waiter records whom it waits for.

use super::desc::{self, File};
use super::fs::Fs;
use super::tree::{Lock, LockKind, Tx};
use fwe_abi::{err, errno, fcntl};
use std::sync::atomic::Ordering::SeqCst;

/// The end of a lock that runs to the end of the file, however far.
const FOREVER: u64 = u64::MAX;

/// The largest offset a lock may reach (Linux's `OFFSET_MAX`).
const OFFSET_MAX: u64 = i64::MAX as u64;

/// Whether `a` and `b` are in each other's way: of the same family
/// (`flock`'s, or record locks), over common bytes, one excluding the
/// other, and not the same owner's.
fn conflicts(a: &Lock, b: &Lock) -> bool {
    let flock = |l: &Lock| l.kind == LockKind::Flock;
    flock(a) == flock(b)
        && a.start < b.end
        && b.start < a.end
        && (a.write || b.write)
        && !same_owner(a, b)
}

fn same_owner(a: &Lock, b: &Lock) -> bool {
    a.kind == b.kind && a.owner == b.owner && (a.kind != LockKind::Posix || a.pid == b.pid)
}

/// The first lock of `locks` in the way of `want`.
fn blocker(locks: &[Lock], want: &Lock) -> Option<Lock> {
    locks.iter().find(|l| conflicts(l, want)).copied()
}

/// `locks` with `owner`'s (as `like` is owned) over `[start, end)` taken
/// out, those running across its edges cut there.
fn without(locks: &[Lock], like: &Lock, start: u64, end: u64) -> Vec<Lock> {
    let mut out = Vec::with_capacity(locks.len() + 1);
    for l in locks {
        if !same_owner(l, like) || l.kind == LockKind::Flock || l.end <= start || end <= l.start {
            out.push(*l);
            continue;
        }
        if l.start < start {
            out.push(Lock { end: start, ..*l });
        }
        if end < l.end {
            out.push(Lock { start: end, ..*l });
        }
    }
    out
}

/// `locks` with `new` in place: the owner's locks it covers replaced, and
/// those of its kind it touches merged with it, as Linux keeps them.
fn with(locks: &[Lock], new: Lock) -> Vec<Lock> {
    let mut out = without(locks, &new, new.start, new.end);
    let mut merged = new;
    out.retain(|l| {
        let touches = l.start <= merged.end && merged.start <= l.end;
        if same_owner(l, &merged) && l.write == merged.write && touches {
            merged.start = merged.start.min(l.start);
            merged.end = merged.end.max(l.end);
            false
        } else {
            true
        }
    });
    out.push(merged);
    out
}

/// The descriptor's file and filesystem, and its description's id.
fn file_of(fd: i32) -> Option<(File, std::sync::Arc<Fs>, u64)> {
    let file = desc::of(fd)?;
    let id = desc::description(fd)?;
    Some((file, file.fs().ok()?, id))
}

/// Take `want` on `file` with `apply` once no lock is in its way, waiting
/// for those in its way to go if `wait` (else `EAGAIN`): 0, or a negated
/// errno.
fn take(
    fs: &Fs,
    file: File,
    want: &Lock,
    wait: bool,
    mut apply: impl FnMut(&mut Tx) -> Result<(), i32>,
) -> i64 {
    let me = crate::sysvipc::me();
    let mut waiting_on: Option<(i32, u64)> = None;
    let mut reap = false;
    let r = loop {
        let mut t = match fs.lock() {
            Ok(t) => t,
            Err(e) => break err(e),
        };
        if reap
            && let Ok(gone) = t.reap(file.ino, desc::alive)
            && let Some(o) = gone.data
        {
            super::data::remove(o);
        }
        let seen = fs.changes().load(SeqCst);
        let in_way = match t.locks(file.ino) {
            Ok(locks) => blocker(&locks, want),
            Err(e) => break err(e),
        };
        if in_way.is_none() {
            break apply(&mut t).map_or_else(err, |()| 0);
        }
        if !wait {
            break err(errno::EAGAIN);
        }
        // A process's record lock waiting for another process's: refused
        // where that one waits, through others, for this one.
        let holder = in_way.filter(|l| l.kind == LockKind::Posix).map(|l| (l.pid, l.owner));
        if want.kind == LockKind::Posix && waiting_on != holder {
            let mut waiters = t.waiters();
            if let Some(old) = waiting_on.take()
                && let Some(i) = waiters.iter().position(|w| *w == [me, old])
            {
                waiters.remove(i);
            }
            if let Some(h) = holder {
                if waits_for(&waiters, h, me) {
                    let _ = t.set_waiters(&waiters);
                    break err(errno::EDEADLK);
                }
                waiters.push([me, h]);
                waiting_on = Some(h);
            }
            if let Err(e) = t.set_waiters(&waiters) {
                waiting_on = None;
                break err(e);
            }
        }
        drop(t);
        if crate::thread::deliverable() != 0 {
            break err(errno::EINTR);
        }
        if crate::thread::pending() & crate::signalfd::watched() != 0 {
            crate::signal::drain_to_signalfd();
        }
        super::wait::wait(fs.changes(), seen, crate::futex::SIGNAL_CHECK);
        // Nothing let go meanwhile: the holder in the way may have ended
        // without letting go.
        reap = fs.changes().load(SeqCst) == seen;
    };
    if let Some(h) = waiting_on
        && let Ok(mut t) = fs.lock()
    {
        let mut waiters = t.waiters();
        if let Some(i) = waiters.iter().position(|w| *w == [me, h]) {
            waiters.remove(i);
            let _ = t.set_waiters(&waiters);
        }
    }
    r
}

/// Whether process `from` waits, through the processes it waits for, for
/// process `to` (each recorded wait whose waiter has ended is passed over).
fn waits_for(waiters: &[[(i32, u64); 2]], from: (i32, u64), to: (i32, u64)) -> bool {
    let mut at = from;
    for _ in 0..waiters.len() {
        if at == to {
            return true;
        }
        let Some(w) = waiters.iter().find(|w| w[0] == at && crate::procreg::alive_kept(w[0]))
        else {
            return false;
        };
        at = w[1];
    }
    at == to
}

/// `flock(fd, op)` of a descriptor of the store (`None` for another).
pub fn flock(fd: i32, op: u64) -> Option<i64> {
    let (file, fs, id) = file_of(fd)?;
    let write = match op & !fcntl::LOCK_NB {
        fcntl::LOCK_SH => false,
        fcntl::LOCK_EX => true,
        fcntl::LOCK_UN => {
            let r = fs.lock().and_then(|mut t| {
                let locks = t.locks(file.ino)?;
                let kept: Vec<Lock> = locks
                    .iter()
                    .filter(|l| !(l.kind == LockKind::Flock && l.owner == id))
                    .copied()
                    .collect();
                t.set_locks(file.ino, &kept)
            });
            return Some(r.map_or_else(err, |()| 0));
        }
        _ => return Some(err(errno::EINVAL)),
    };
    let want = Lock { kind: LockKind::Flock, write, pid: 0, owner: id, start: 0, end: FOREVER };
    // A lock of the other kind the description holds is let go first, as
    // Linux does (so a waiting change lets others in meanwhile).
    let changed = fs.lock().and_then(|mut t| {
        let locks = t.locks(file.ino)?;
        if locks.contains(&want) {
            return Ok(true);
        }
        if locks.iter().any(|l| l.kind == LockKind::Flock && l.owner == id) {
            let kept: Vec<Lock> = locks
                .iter()
                .filter(|l| !(l.kind == LockKind::Flock && l.owner == id))
                .copied()
                .collect();
            t.set_locks(file.ino, &kept)?;
        }
        Ok(false)
    });
    match changed {
        Ok(true) => return Some(0),
        Ok(false) => {}
        Err(e) => return Some(err(e)),
    }
    Some(take(&fs, file, &want, op & fcntl::LOCK_NB == 0, |t| {
        let mut locks = t.locks(file.ino)?;
        locks.push(want);
        t.set_locks(file.ino, &locks)
    }))
}

/// The range `lock` names on descriptor `fd` of a file of `size` bytes:
/// `[start, end)`.
fn range(fd: i32, lock: &fwe_abi::Flock, size: u64) -> Result<(u64, u64), i32> {
    let base: i64 = match lock.l_whence as u64 {
        fcntl::SEEK_SET => 0,
        fcntl::SEEK_CUR => {
            // SAFETY: plain host call; the host keeps the description's
            // position.
            let pos = unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) };
            if pos < 0 {
                return Err(crate::host::errno_to_linux(crate::host::last_errno()));
            }
            pos
        }
        fcntl::SEEK_END => size as i64,
        _ => return Err(errno::EINVAL),
    };
    let start = base.checked_add(lock.l_start).ok_or(errno::EOVERFLOW)?;
    let (start, end) = match lock.l_len {
        0 => (start, None),
        n if n > 0 => (start, Some(start.checked_add(n).ok_or(errno::EOVERFLOW)?)),
        n => (start.checked_add(n).ok_or(errno::EINVAL)?, Some(start)),
    };
    if start < 0 {
        return Err(errno::EINVAL);
    }
    match end {
        Some(e) if e as u64 - 1 > OFFSET_MAX => Err(errno::EOVERFLOW),
        Some(e) => Ok((start as u64, e as u64)),
        None => Ok((start as u64, FOREVER)),
    }
}

/// The lock `lock` asks for through `fd`, `cmd` telling whose: a
/// process's or the description's `id`'s.
fn wanted(fd: i32, cmd: u64, lock: &fwe_abi::Flock, size: u64, id: u64) -> Result<Lock, i32> {
    let (start, end) = range(fd, lock, size)?;
    let write = match lock.l_type {
        fcntl::F_RDLCK => false,
        fcntl::F_WRLCK => true,
        fcntl::F_UNLCK => false,
        _ => return Err(errno::EINVAL),
    };
    let ofd = matches!(cmd, fcntl::F_OFD_GETLK | fcntl::F_OFD_SETLK | fcntl::F_OFD_SETLKW);
    Ok(if ofd {
        Lock { kind: LockKind::Ofd, write, pid: 0, owner: id, start, end }
    } else {
        let (pid, start_time) = crate::sysvipc::me();
        Lock { kind: LockKind::Posix, write, pid, owner: start_time, start, end }
    })
}

/// `fcntl(fd, F_SETLK, F_SETLKW or their F_OFD_ forms, lock)` of a
/// descriptor of the store (`None` for another).
pub fn set(fd: i32, cmd: u64, lock: &fwe_abi::Flock) -> Option<i64> {
    let (file, fs, id) = file_of(fd)?;
    let size = match fs.lock().and_then(|t| t.stat(file.ino)) {
        Ok(st) => st.size,
        Err(e) => return Some(err(e)),
    };
    let want = match wanted(fd, cmd, lock, size, id) {
        Ok(l) => l,
        Err(e) => return Some(err(e)),
    };
    // A lock to read is taken through a descriptor that reads, one to
    // write through one that writes.
    // SAFETY: plain host call on the guest's descriptor.
    let mode = unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_ACCMODE;
    let refused = match lock.l_type {
        fcntl::F_RDLCK => mode == libc::O_WRONLY,
        fcntl::F_WRLCK => mode == libc::O_RDONLY,
        _ => false,
    };
    if refused {
        return Some(err(errno::EBADF));
    }
    if lock.l_type == fcntl::F_UNLCK {
        let r = fs.lock().and_then(|mut t| {
            let locks = t.locks(file.ino)?;
            t.set_locks(file.ino, &without(&locks, &want, want.start, want.end))
        });
        return Some(r.map_or_else(err, |()| 0));
    }
    let wait = matches!(cmd, fcntl::F_SETLKW | fcntl::F_OFD_SETLKW);
    Some(take(&fs, file, &want, wait, |t| {
        let locks = t.locks(file.ino)?;
        t.set_locks(file.ino, &with(&locks, want))
    }))
}

/// `fcntl(fd, F_GETLK or F_OFD_GETLK, lock)` of a descriptor of the store
/// (`None` for another): the first lock in the way of the one `lock` asks
/// for, or `lock` as asked with its type `F_UNLCK`.
pub fn get(fd: i32, cmd: u64, lock: &fwe_abi::Flock) -> Option<Result<fwe_abi::Flock, i32>> {
    let (file, fs, id) = file_of(fd)?;
    Some((|| {
        let t = fs.lock()?;
        let size = t.stat(file.ino)?.size;
        if lock.l_type == fcntl::F_UNLCK {
            return Err(errno::EINVAL);
        }
        let want = wanted(fd, cmd, lock, size, id)?;
        let Some(l) = blocker(&t.locks(file.ino)?, &want) else {
            return Ok(fwe_abi::Flock { l_type: fcntl::F_UNLCK, ..*lock });
        };
        Ok(fwe_abi::Flock {
            l_type: if l.write { fcntl::F_WRLCK } else { fcntl::F_RDLCK },
            l_whence: fcntl::SEEK_SET as i16,
            l_start: l.start as i64,
            l_len: if l.end == FOREVER { 0 } else { (l.end - l.start) as i64 },
            // A description's lock is no process's.
            l_pid: match l.kind {
                LockKind::Posix => crate::sysvipc::guest_pid(l.pid),
                _ => -1,
            },
        })
    })())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn posix(pid: i32, write: bool, start: u64, end: u64) -> Lock {
        Lock { kind: LockKind::Posix, write, pid, owner: 7, start, end }
    }

    /// A process's record locks are cut, replaced and merged as Linux
    /// keeps them; another's in the way conflict, a `flock` lock never.
    #[test]
    fn ranges() {
        let l = with(&[], posix(1, true, 0, 100));
        let l = with(&l, posix(1, false, 40, 60));
        let mut got: Vec<(bool, u64, u64)> = l.iter().map(|l| (l.write, l.start, l.end)).collect();
        got.sort_by_key(|g| g.1);
        assert_eq!(got, vec![(true, 0, 40), (false, 40, 60), (true, 60, 100)]);
        let l = with(&l, posix(1, true, 40, 60));
        assert_eq!(l.len(), 1);
        assert_eq!((l[0].start, l[0].end), (0, 100));
        let l = without(&l, &posix(1, true, 0, 0), 10, 20);
        assert_eq!(l.len(), 2);
        assert!(blocker(&l, &posix(2, false, 15, 16)).is_none());
        assert!(blocker(&l, &posix(2, false, 5, 16)).is_some());
        assert!(blocker(&l, &posix(1, true, 5, 16)).is_none());
        let f =
            Lock { kind: LockKind::Flock, write: true, pid: 0, owner: 9, start: 0, end: FOREVER };
        assert!(blocker(&l, &f).is_none());
        let ofd = Lock { kind: LockKind::Ofd, write: false, pid: 0, owner: 9, start: 0, end: 1 };
        assert!(blocker(&l, &ofd).is_some());
    }
}
