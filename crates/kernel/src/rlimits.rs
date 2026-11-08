//! The resource limits fwe keeps itself:
//!
//! - those the host has no counterpart of (`RLIMIT_NICE`, `RLIMIT_RTPRIO`,
//!   `RLIMIT_MSGQUEUE` and the like);
//! - `RLIMIT_MEMLOCK`, since fwe wires no memory for the guest (see
//!   `Kernel::sys_mlock`);
//! - `RLIMIT_CORE`, since fwe writes the guest's core dumps (the host's
//!   limit is kept at 0);
//! - `RLIMIT_STACK`, since the guest's stack is fwe's, not the host
//!   thread's (whose limit macOS will not set below the stack it has);
//! - `RLIMIT_CPU`, whose soft limit the host's carries, but whose hard
//!   limit macOS does not enforce: past the soft limit fwe has the host
//!   signal again every second, as Linux does, and at the hard limit ends
//!   the process with `SIGKILL` ([`cpu_signal`]);
//! - `RLIMIT_NPROC`, which fwe enforces at `fork` by the user's fwe
//!   processes, so a privileged guest may raise it as Linux lets it (the
//!   host's, which only the host's root may raise, applies as well).
//!
//! Each starts at Linux's default (the core, stack and process limits at
//! the host's, as the user set them) and is set as Linux sets one: the soft
//! limit no higher than the hard, the hard one raised only with
//! `CAP_SYS_RESOURCE`. They are carried across an `execve` that re-executes
//! fwe, and a fork child has its parent's.

use crate::snapshot::{Dec, Enc};
use fwe_abi::{errno, resource as r};
use std::sync::Mutex;

/// Linux's resources, by number.
const COUNT: usize = r::RLIM_NLIMITS as usize;

static LIMITS: Mutex<Option<[(u64, u64); COUNT]>> = Mutex::new(None);

/// A process's limit of `res` as Linux starts one out (for those kept
/// here).
fn default_of(res: u64) -> (u64, u64) {
    let host = match res {
        // fwe's own core limit is then kept at 0 ([`host_core_off`]), the
        // guest's dumps being fwe's to write ([`crate::coredump`]).
        r::RLIMIT_CORE => Some(libc::RLIMIT_CORE),
        r::RLIMIT_STACK => Some(libc::RLIMIT_STACK),
        r::RLIMIT_NPROC => Some(libc::RLIMIT_NPROC),
        r::RLIMIT_CPU => Some(libc::RLIMIT_CPU),
        _ => None,
    };
    if let Some(h) = host {
        // The host's, as the first process found it.
        let mut l = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        // SAFETY: a valid out-parameter.
        unsafe { libc::getrlimit(h, &mut l) };
        return (crate::host::rlim_to_linux(l.rlim_cur), crate::host::rlim_to_linux(l.rlim_max));
    }
    let v = match res {
        r::RLIMIT_SIGPENDING => 63_432,
        r::RLIMIT_MSGQUEUE => 819_200,
        r::RLIMIT_NICE | r::RLIMIT_RTPRIO => 0,
        // 8 MiB, Linux's since 5.16.
        r::RLIMIT_MEMLOCK => 8 << 20,
        _ => r::RLIM_INFINITY,
    };
    (v, v)
}

fn with<R>(f: impl FnOnce(&mut [(u64, u64); COUNT]) -> R) -> R {
    let mut g = LIMITS.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(|| std::array::from_fn(|i| default_of(i as u64))))
}

/// The guest's core limit taken from the host's, the host's set to 0:
/// macOS never writes a core of an fwe process (all of its reserved
/// memory, gigabytes), whatever the guest's limit.
pub fn host_core_off() {
    get(r::RLIMIT_CORE);
    let (soft, hard) = get(r::RLIMIT_CPU);
    cpu_to_host(soft, hard);
    let off = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: a valid limit; lowering one needs no privilege.
    unsafe { libc::setrlimit(libc::RLIMIT_CORE, &off) };
}

/// Whether limit `res` is one kept here.
pub fn kept(res: u64) -> bool {
    res < r::RLIM_NLIMITS
        && (res == r::RLIMIT_MEMLOCK
            || (res != r::RLIMIT_NOFILE && crate::host::rlimit_to_host(res).is_none()))
}

/// Limit `res` (soft, hard).
pub fn get(res: u64) -> (u64, u64) {
    with(|l| l[res as usize])
}

/// Set limit `res` to (`soft`, `hard`), as Linux does: `EINVAL` for a soft
/// limit past the hard, `EPERM` for raising the hard one without
/// `CAP_SYS_RESOURCE` (`privileged`).
pub fn set(res: u64, soft: u64, hard: u64, privileged: bool) -> Result<(), i32> {
    if soft > hard {
        return Err(errno::EINVAL);
    }
    with(|l| {
        let slot = &mut l[res as usize];
        if hard > slot.1 && !privileged {
            return Err(errno::EPERM);
        }
        *slot = (soft, hard);
        Ok(())
    })?;
    if res == r::RLIMIT_CPU {
        cpu_to_host(soft, hard);
    }
    Ok(())
}

/// The guest's CPU limits, in seconds, for the host's `SIGXCPU` handler
/// (which takes no lock).
static CPU: [std::sync::atomic::AtomicU64; 2] =
    [std::sync::atomic::AtomicU64::new(u64::MAX), std::sync::atomic::AtomicU64::new(u64::MAX)];

/// The guest's CPU limits are (`soft`, `hard`): the host signals at the
/// soft one.
fn cpu_to_host(soft: u64, hard: u64) {
    use std::sync::atomic::Ordering::SeqCst;
    CPU[0].store(soft, SeqCst);
    CPU[1].store(hard, SeqCst);
    let mut l = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: valid limit structures.
    unsafe {
        libc::getrlimit(libc::RLIMIT_CPU, &mut l);
        l.rlim_cur = crate::host::rlim_to_host(soft).min(l.rlim_max);
        libc::setrlimit(libc::RLIMIT_CPU, &l);
    }
}

/// The host's `SIGXCPU` came: whether it is the guest's to take. Past the
/// hard limit the process ends of `SIGKILL` (by fwe's relay of it, which
/// takes a VM down first) and it is not; otherwise the host is to signal
/// again in a second. Async-signal-safe.
pub fn cpu_signal() -> bool {
    use std::sync::atomic::Ordering::SeqCst;
    let hard = CPU[1].load(SeqCst);
    // SAFETY: an all-zero rusage is a valid out-parameter.
    let mut u: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: plain host call.
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut u) };
    let used = (u.ru_utime.tv_sec + u.ru_stime.tv_sec) as u64;
    if hard != r::RLIM_INFINITY && used >= hard {
        // SAFETY: getpid cannot fail.
        let me = unsafe { libc::getpid() };
        crate::signote::note(me, crate::host::KILL_RELAY);
        // SAFETY: plain host call; the relay ends this process.
        unsafe { libc::kill(me, crate::host::KILL_RELAY) };
        return false;
    }
    let mut l = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: valid limit structures.
    unsafe {
        libc::getrlimit(libc::RLIMIT_CPU, &mut l);
        l.rlim_cur = crate::host::rlim_to_host(used + 1).min(l.rlim_max);
        libc::setrlimit(libc::RLIMIT_CPU, &l);
    }
    true
}

/// Write the limits into the state an `execve` of fwe carries.
pub fn save(e: &mut Enc) {
    with(|l| {
        for &(soft, hard) in l.iter() {
            e.u64(soft);
            e.u64(hard);
        }
    })
}

/// Take the limits [`save`] wrote.
pub fn load(d: &mut Dec) {
    let mut l = [(0, 0); COUNT];
    for slot in &mut l {
        *slot = (d.u64(), d.u64());
    }
    *LIMITS.lock().unwrap_or_else(|e| e.into_inner()) = Some(l);
    let (soft, hard) = l[r::RLIMIT_CPU as usize];
    cpu_to_host(soft, hard);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_are_set_as_linux_sets_them() {
        assert!(kept(r::RLIMIT_MEMLOCK) && kept(r::RLIMIT_NICE));
        assert!(kept(r::RLIMIT_STACK) && kept(r::RLIMIT_CORE));
        assert!(!kept(r::RLIMIT_NOFILE) && !kept(r::RLIMIT_AS));
        let res = r::RLIMIT_RTTIME;
        let (_, hard) = get(res);
        assert_eq!(set(res, 10, 5, true), Err(errno::EINVAL));
        set(res, 5, 10, true).unwrap();
        assert_eq!(get(res), (5, 10));
        assert_eq!(set(res, 5, 20, false), Err(errno::EPERM));
        set(res, 5, 8, false).unwrap();
        set(res, hard, hard, true).unwrap();
    }
}
