//! File leases (`F_SETLEASE`) as Linux breaks them, across fwe processes.
//!
//! Each lease is kept in a record every fwe process shares: the file (host
//! device and inode), the process and descriptor holding it, its type, the
//! signal its holder chose (`F_SETSIG`), and while it is being broken what
//! it must become and by when. An open of the file that conflicts with a
//! lease (any open, with a write lease; one to write, or a truncation, with
//! a read lease) breaks it: the holder is sent its signal (`SIGIO` by
//! default, or the chosen one with the descriptor, as `POLL_MSG`), and the
//! open waits until the holder lets the lease go or downgrades it, or until
//! `fs.lease-break-time` seconds pass and it is taken away; a non-blocking
//! open fails with `EWOULDBLOCK` instead, the break begun.

use crate::shared::{Data, Record};
use crate::snapshot::{Dec, Enc};
use fwe_abi::{errno, fcntl};

/// One lease.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Lease {
    dev: u64,
    ino: u64,
    pid: i32,
    start: u64,
    fd: i32,
    kind: i16,
    /// The signal its holder chose (0: `SIGIO`).
    sig: u32,
    /// Being broken: what it must become (`F_RDLCK`, or `F_UNLCK`), and
    /// when it is taken away, in seconds since the epoch.
    breaking: Option<(i16, u64)>,
}

#[derive(Clone, Debug, Default)]
struct Leases(Vec<Lease>);

impl Data for Leases {
    fn encode(&self, e: &mut Enc) {
        e.u64(self.0.len() as u64);
        for l in &self.0 {
            e.u64(l.dev);
            e.u64(l.ino);
            e.i32(l.pid);
            e.u64(l.start);
            e.i32(l.fd);
            e.i32(i32::from(l.kind));
            e.u32(l.sig);
            e.bool(l.breaking.is_some());
            let (t, d) = l.breaking.unwrap_or((0, 0));
            e.i32(i32::from(t));
            e.u64(d);
        }
    }

    fn decode(d: &mut Dec) -> Self {
        let n = d.count(53);
        Leases(
            (0..n)
                .map(|_| {
                    let (dev, ino, pid, start, fd) = (d.u64(), d.u64(), d.i32(), d.u64(), d.i32());
                    let (kind, sig, breaking) = (d.i32() as i16, d.u32(), d.bool());
                    let (t, deadline) = (d.i32() as i16, d.u64());
                    Lease {
                        dev,
                        ino,
                        pid,
                        start,
                        fd,
                        kind,
                        sig,
                        breaking: breaking.then_some((t, deadline)),
                    }
                })
                .collect(),
        )
    }
}

/// Whether this process has held a lease, so a close looks.
static HELD: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn record() -> Option<&'static Record<Leases>> {
    static R: std::sync::OnceLock<Option<Record<Leases>>> = std::sync::OnceLock::new();
    R.get_or_init(|| Record::named("leases", 0, Leases::default).ok()).as_ref()
}

/// The record, if a process has made it (an open of a file no lease was
/// ever taken on costs a look only).
fn existing() -> Option<&'static Record<Leases>> {
    use std::os::unix::ffi::OsStrExt;
    // Once made, the record stays: no more looks.
    static FOUND: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if FOUND.load(std::sync::atomic::Ordering::Relaxed) {
        return record();
    }
    let mut dir = crate::fs::shm::user_dir().ok()?;
    dir.extend_from_slice(format!("/v{}-leases", crate::shared::FORMAT).as_bytes());
    std::fs::metadata(std::ffi::OsStr::from_bytes(&dir)).ok()?;
    let r = record();
    FOUND.store(r.is_some(), std::sync::atomic::Ordering::Relaxed);
    r
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// This process: host pid and start time.
fn me() -> (i32, u64) {
    let pid = crate::host::pid();
    (pid, crate::procreg::host_info(pid).map_or(0, |i| i.0))
}

/// Drop leases of ended processes and those whose break ran out.
fn tidy(l: &mut Leases, now: u64) {
    l.0.retain(|e| {
        crate::procreg::alive((e.pid, e.start)) && e.breaking.is_none_or(|(_, by)| by > now)
    });
}

/// The lease descriptor `fd` holds, as `F_GETLEASE` reports it: while it
/// is being broken, what it must become.
pub fn get(fd: i32) -> i16 {
    let Some(r) = existing() else { return fcntl::F_UNLCK };
    let (pid, start) = me();
    let now = now();
    r.get()
        .0
        .iter()
        .find(|e| e.pid == pid && e.start == start && e.fd == fd)
        .filter(|e| e.breaking.is_none_or(|(_, by)| by > now))
        .map_or(fcntl::F_UNLCK, |e| e.breaking.map_or(e.kind, |(to, _)| to))
}

/// `F_SETLEASE` of `kind` on descriptor `fd` (of file `dev`, `ino`), the
/// checks of the caller and its own descriptors made: while the lease is
/// being broken, only to what it must become (or below), else `EAGAIN`.
pub fn set(fd: i32, dev: u64, ino: u64, kind: i16) -> Result<(), i32> {
    let r = record().ok_or(errno::ENOMEM)?;
    let (pid, start) = me();
    let sig = crate::fdstate::get(fd).sig;
    HELD.store(true, std::sync::atomic::Ordering::SeqCst);
    r.update(|l| {
        tidy(l, now());
        let i = l.0.iter().position(|e| e.pid == pid && e.start == start && e.fd == fd);
        if kind == fcntl::F_UNLCK {
            if let Some(i) = i {
                l.0.remove(i);
            }
            return Ok(());
        }
        match i {
            Some(i) => {
                let e = &mut l.0[i];
                if let Some((to, _)) = e.breaking {
                    if to == fcntl::F_UNLCK || kind == fcntl::F_WRLCK {
                        return Err(errno::EAGAIN);
                    }
                    e.breaking = None;
                }
                e.kind = kind;
                e.sig = sig;
            }
            None => l.0.push(Lease { dev, ino, pid, start, fd, kind, sig, breaking: None }),
        }
        Ok(())
    })
}

/// Descriptor `fd`'s signal is `sig` now (`F_SETSIG`): its lease's too.
pub fn signal_set(fd: i32, sig: u32) {
    if !HELD.load(std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    let Some(r) = existing() else { return };
    let (pid, start) = me();
    let _ = r.update_maybe(|l| {
        let e = l.0.iter_mut().find(|e| e.pid == pid && e.start == start && e.fd == fd);
        let changed = e.is_some();
        if let Some(e) = e {
            e.sig = sig;
        }
        Ok(((), changed))
    });
}

/// Descriptor `fd` closed: its lease goes.
pub fn closed(fd: i32) {
    if !HELD.load(std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    let Some(r) = existing() else { return };
    let (pid, start) = me();
    let _ = r.update_maybe(|l| {
        let before = l.0.len();
        l.0.retain(|e| !(e.pid == pid && e.start == start && e.fd == fd));
        Ok(((), l.0.len() != before))
    });
}

/// An open of file `dev`, `ino` (to write, or a truncation, if `write`) is
/// about to happen: break the leases it conflicts with, and wait until they
/// are let go, downgraded or taken away (`EWOULDBLOCK` if `nonblock`).
pub fn break_for(dev: u64, ino: u64, write: bool, nonblock: bool) -> Result<(), i32> {
    let Some(r) = existing() else { return Ok(()) };
    if !r.get().0.iter().any(|e| e.dev == dev && e.ino == ino) {
        return Ok(());
    }
    let wait = crate::sysctl::number(b"fs/lease-break-time").unwrap_or(45).max(0) as u64;
    loop {
        let now = now();
        let mut signals: Vec<(i32, u32, i32)> = Vec::new();
        let pending = r.update(|l| {
            tidy(l, now);
            let mut pending = false;
            for e in l.0.iter_mut().filter(|e| e.dev == dev && e.ino == ino) {
                let target = if write { fcntl::F_UNLCK } else { fcntl::F_RDLCK };
                let kind = e.breaking.map_or(e.kind, |(to, _)| to);
                let conflicts = kind == fcntl::F_WRLCK || (write && kind == fcntl::F_RDLCK);
                if !conflicts {
                    continue;
                }
                pending = true;
                match e.breaking {
                    // Already being broken: to the lower of the two.
                    Some((to, by)) => {
                        let lower = if to == fcntl::F_UNLCK { to } else { target };
                        e.breaking = Some((lower, by));
                    }
                    None => {
                        e.breaking = Some((target, now + wait));
                        signals.push((e.pid, e.sig, e.fd));
                    }
                }
            }
            Ok(pending)
        })?;
        for (pid, sig, fd) in signals {
            tell(pid, sig, fd);
        }
        if !pending {
            return Ok(());
        }
        if nonblock {
            return Err(errno::EWOULDBLOCK);
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// Tell the holder (host pid `pid`) its lease on descriptor `fd` is being
/// broken: its chosen signal `sig`, with the descriptor (`POLL_MSG`), or
/// `SIGIO` from the kernel.
fn tell(pid: i32, sig: u32, fd: i32) {
    use fwe_abi::signal;
    let (sig, code) =
        if sig == 0 { (signal::SIGIO, signal::SI_KERNEL) } else { (u64::from(sig), POLL_MSG) };
    let Some(h) = crate::host::signal_to_host(sig) else { return };
    crate::signote::note_with(pid, h, code, fd as u64);
    if crate::host::kill_process(pid, h) != 0 {
        crate::signote::unnote(pid, h);
    }
}

/// `si_code` of a lease break signal carrying the descriptor.
pub const POLL_MSG: i32 = 3;
/// Its `si_band`: Linux's `POLLIN | POLLRDNORM | POLLMSG`.
pub const POLL_MSG_BAND: i64 = 0x1 | 0x40 | 0x400;
