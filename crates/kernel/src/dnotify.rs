//! dnotify: `fcntl(F_NOTIFY)`, a signal when a directory or what is in it
//! changes.
//!
//! A dnotify watch is a watch in inotify's registry ([`crate::inotify`]),
//! so the events fwe raises as its processes act on files reach it. In
//! place of an instance's socket it names its owner and descriptor
//! (`dnotify:<pid>:<start>:<fd>`), and an event is a signal: the
//! descriptor's `F_SETSIG` signal with `si_fd` and `POLL_MSG`, or a plain
//! `SIGIO`. The owner's own events are posted as the call that raises
//! them runs, as Linux sends them; another process's reach it as a
//! `SIGIO` note naming the descriptor, which it turns into that signal
//! ([`crate::signal`]).

use crate::inotify::{self, Watch};
use fwe_abi::errno;
use fwe_abi::fcntl::{
    DN_ACCESS, DN_ATTRIB, DN_CREATE, DN_DELETE, DN_MODIFY, DN_MULTISHOT, DN_RENAME,
};
use fwe_abi::inotify::*;

/// What a watch's name starts with.
const PREFIX: &[u8] = b"dnotify:";

/// An event only dnotify hears: a rename within one directory
/// (`DN_RENAME`), raised on the directory's watches.
pub const IN_DN_RENAME: u32 = 1 << 27;

/// `si_code` and `si_band` of the signal (`POLL_MSG`: `POLLIN |
/// POLLRDNORM | POLLMSG`).
pub const POLL_MSG: i32 = 3;
const BAND: i64 = 0x441;

/// Whether `inst` names a dnotify watch's owner.
pub fn is_dnotify(inst: &[u8]) -> bool {
    inst.starts_with(PREFIX)
}

/// The inotify events for `DN_*` mask `arg` (a one-shot watch without
/// `DN_MULTISHOT`).
fn events(arg: u64) -> u32 {
    let mut m = 0;
    if arg & DN_ACCESS != 0 {
        m |= IN_ACCESS;
    }
    if arg & DN_MODIFY != 0 {
        m |= IN_MODIFY;
    }
    if arg & DN_CREATE != 0 {
        m |= IN_CREATE | IN_MOVED_TO;
    }
    if arg & DN_DELETE != 0 {
        m |= IN_DELETE | IN_MOVED_FROM;
    }
    if arg & DN_RENAME != 0 {
        m |= IN_DN_RENAME;
    }
    if arg & DN_ATTRIB != 0 {
        m |= IN_ATTRIB;
    }
    if arg & DN_MULTISHOT == 0 {
        m |= IN_ONESHOT;
    }
    m
}

fn name_of(fd: i32) -> Vec<u8> {
    let me = crate::sysvipc::me();
    [PREFIX, format!("{}:{}:{fd}", me.0, me.1).as_bytes()].concat()
}

/// `fcntl(fd, F_NOTIFY, arg)`: watch directory `fd` for the events `arg`
/// names, or no longer (none named).
pub fn set(fd: i32, arg: u64) -> Result<(), i32> {
    let s = inotify::subject_of_fd(fd).ok_or(errno::EBADF)?;
    if !s.dir {
        return Err(errno::ENOTDIR);
    }
    let name = name_of(fd);
    let r = inotify::registry().ok_or(errno::ENOMEM)?;
    let mask = events(arg);
    let watching = arg & !DN_MULTISHOT != 0;
    r.update_maybe(|t| {
        let before = t.watches.len();
        t.watches.retain(|w| w.inst != name);
        if watching {
            t.watches.push(Watch {
                inst: name.clone(),
                wd: fd,
                dev: s.dev,
                ino: s.ino,
                mask,
                ns_path: Vec::new(),
                mnt: Vec::new(),
            });
        }
        Ok(((), watching || t.watches.len() != before))
    })
}

/// `fd` is closed: its watch goes.
pub fn closed(fd: i32) {
    if !inotify::watching() {
        return;
    }
    let name = name_of(fd);
    let Some(r) = inotify::registry() else { return };
    if !r.get().watches.iter().any(|w| w.inst == name) {
        return;
    }
    let _ = r.update_maybe(|t| {
        let before = t.watches.len();
        t.watches.retain(|w| w.inst != name);
        Ok(((), t.watches.len() != before))
    });
}

/// Signal the owner of watch `inst` of an event with `mask`: false if it
/// has gone.
pub fn deliver(inst: &[u8], mask: u32) -> bool {
    // What a watch hears as it goes (`IN_IGNORED`) is no change.
    if mask & (IN_IGNORED | IN_UNMOUNT | IN_Q_OVERFLOW | IN_DELETE_SELF) != 0 {
        return true;
    }
    let text = String::from_utf8_lossy(&inst[PREFIX.len()..]).into_owned();
    let mut parts = text.split(':').map(|p| p.parse::<u64>().ok());
    let (Some(Some(pid)), Some(Some(start)), Some(Some(fd))) =
        (parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let (pid, fd) = (pid as i32, fd as i32);
    if (pid, start) == crate::sysvipc::me() {
        post(fd);
        return true;
    }
    if !crate::procreg::alive((pid, start)) {
        return false;
    }
    let value = fd as u32 as u64;
    if crate::signote::queue(pid, fwe_abi::signal::SIGIO, POLL_MSG, value).is_err() {
        return false;
    }
    crate::host::kill_process(pid, crate::host::WAKE_SIGNAL) == 0
}

/// Post the signal for an event on this process's watch of `fd`.
pub fn post(fd: i32) {
    let sig = crate::fdstate::get(fd).sig;
    if sig == 0 {
        let info =
            crate::thread::SigInfo { code: fwe_abi::signal::SI_KERNEL, ..Default::default() };
        crate::thread::post_process(fwe_abi::signal::SIGIO, info);
    } else {
        let info =
            crate::thread::SigInfo { code: POLL_MSG, poll: Some((fd, BAND)), ..Default::default() };
        crate::thread::post_process(u64::from(sig), info);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dnotify_masks_are_linuxs() {
        assert_eq!(events(DN_ATTRIB | DN_MULTISHOT), IN_ATTRIB);
        assert_eq!(events(DN_DELETE), IN_DELETE | IN_MOVED_FROM | IN_ONESHOT);
        assert_eq!(events(DN_CREATE | DN_MULTISHOT), IN_CREATE | IN_MOVED_TO);
        assert_eq!(events(DN_RENAME | DN_MULTISHOT), IN_DN_RENAME);
    }
}
