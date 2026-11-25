//! Numbers of different kinds kept apart by their types: a host process's
//! pid is a [`HostPid`], and a thread as every process can name it is a
//! [`Tid`]; neither converts from a guest-visible number (one a pid
//! namespace numbers), or to the other, without saying so. A Linux signal
//! is a [`LinuxSig`], one of Linux's 64, whose bit in a set it names. Each
//! is the
//! bare number in memory (`#[repr(transparent)]`), so a call that takes
//! one costs what it did with the number.

use std::num::{NonZeroI32, NonZeroU8};

/// A host process: a pid above 0. A number that is not one (0 and the
/// negative numbers name process groups, or every process, to the host's
/// `kill`) has no `HostPid`, so nothing typed so can signal more than one
/// process.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct HostPid(NonZeroI32);

impl HostPid {
    /// The host process `pid`, if `pid` is one (above 0).
    #[inline]
    pub const fn new(pid: libc::pid_t) -> Option<HostPid> {
        if pid <= 0 {
            return None;
        }
        match NonZeroI32::new(pid) {
            Some(p) => Some(HostPid(p)),
            None => None,
        }
    }

    /// `pid`, which the host gave as a process's (its `getpid`, a child's
    /// `fork`).
    ///
    /// # Safety
    /// `pid` MUST be above 0.
    #[inline]
    pub const unsafe fn new_unchecked(pid: libc::pid_t) -> HostPid {
        // SAFETY: above 0, so not 0, as the caller promises.
        HostPid(unsafe { NonZeroI32::new_unchecked(pid) })
    }

    /// The pid, for the host's calls.
    #[inline]
    pub const fn get(self) -> libc::pid_t {
        self.0.get()
    }
}

impl std::fmt::Display for HostPid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.get().fmt(f)
    }
}

/// A thread as fwe names it to every process, as Linux's initial pid
/// namespace numbers it: a process's main thread by its host pid, any
/// other by a number of fwe's shared counter (above every host pid), which
/// a thread in a pid namespace of fwe's takes too, beside its numbers
/// there. No two live threads of fwe's processes have the same one, so it
/// names a thread to another process (its tracer, a signal's sender, a
/// reader of its state) whatever namespaces either is in.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Tid(NonZeroI32);

impl Tid {
    /// The thread `id` names, if it can name one (above 0).
    #[inline]
    pub const fn new(id: i32) -> Option<Tid> {
        match HostPid::new(id) {
            Some(p) => Some(Tid(p.0)),
            None => None,
        }
    }

    /// Process `pid`'s main thread.
    #[inline]
    pub const fn main_of(pid: HostPid) -> Tid {
        Tid(pid.0)
    }

    /// The id, for a record shared with other processes.
    #[inline]
    pub const fn get(self) -> i32 {
        self.0.get()
    }
}

/// A Linux signal: one of 1 to 64 ([`fwe_abi::signal::NSIG`]). A number
/// outside them (a `clone`'s exit signal can be any up to 255) has none.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct LinuxSig(NonZeroU8);

impl LinuxSig {
    /// `SIGCHLD`, which tells a child's end unless it chose another.
    pub const SIGCHLD: LinuxSig = match LinuxSig::new(fwe_abi::signal::SIGCHLD) {
        Some(s) => s,
        None => panic!("SIGCHLD is a signal"),
    };

    /// Linux signal `sig`, if it is one.
    #[inline]
    pub const fn new(sig: u64) -> Option<LinuxSig> {
        if sig == 0 || sig > fwe_abi::signal::NSIG {
            return None;
        }
        match NonZeroU8::new(sig as u8) {
            Some(s) => Some(LinuxSig(s)),
            None => None,
        }
    }

    /// The signal's number.
    #[inline]
    pub const fn get(self) -> u64 {
        self.0.get() as u64
    }

    /// Its bit in a Linux signal set.
    #[inline]
    pub const fn bit(self) -> u64 {
        1 << (self.0.get() - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_number_above_0_is_a_host_process() {
        assert_eq!(HostPid::new(0), None);
        assert_eq!(HostPid::new(-1), None);
        assert_eq!(HostPid::new(i32::MIN), None);
        assert_eq!(HostPid::new(1).map(HostPid::get), Some(1));
        assert_eq!(HostPid::new(i32::MAX).map(HostPid::get), Some(i32::MAX));
    }

    #[test]
    fn a_host_pid_or_none_is_the_size_of_a_pid() {
        assert_eq!(size_of::<Option<HostPid>>(), size_of::<libc::pid_t>());
        assert_eq!(size_of::<Option<Tid>>(), size_of::<i32>());
    }

    #[test]
    fn a_signal_is_one_of_linuxs_64() {
        assert_eq!(LinuxSig::new(0), None);
        assert_eq!(LinuxSig::new(65), None);
        assert_eq!(LinuxSig::new(255), None);
        assert_eq!(LinuxSig::new(1).map(LinuxSig::bit), Some(1));
        assert_eq!(LinuxSig::new(64).map(LinuxSig::bit), Some(1 << 63));
        assert_eq!(LinuxSig::new(17).map(LinuxSig::get), Some(17));
        assert_eq!(size_of::<Option<LinuxSig>>(), 1);
    }

    #[test]
    fn a_main_thread_is_named_by_its_process() {
        let p = HostPid::new(4321).unwrap();
        assert_eq!(Tid::main_of(p).get(), 4321);
        assert_eq!(Tid::new(0), None);
        assert_eq!(Tid::new(-7), None);
    }
}
