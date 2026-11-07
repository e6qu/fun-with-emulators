//! The resource limits fwe keeps itself: those the host has no counterpart
//! of (`RLIMIT_NICE`, `RLIMIT_RTPRIO`, `RLIMIT_MSGQUEUE` and the like), and
//! `RLIMIT_MEMLOCK`, since fwe wires no memory for the guest (see
//! `Kernel::sys_mlock`). Each starts at Linux's default and is set as Linux
//! sets one: the soft limit no higher than the hard, the hard one raised only
//! with `CAP_SYS_RESOURCE`. They are carried across an `execve` that
//! re-executes fwe, and a fork child has its parent's.

use crate::snapshot::{Dec, Enc};
use fwe_abi::{errno, resource as r};
use std::sync::Mutex;

/// Linux's resources, by number.
const COUNT: usize = r::RLIM_NLIMITS as usize;

static LIMITS: Mutex<Option<[(u64, u64); COUNT]>> = Mutex::new(None);

/// A process's limit of `res` as Linux starts one out (for those kept
/// here).
fn default_of(res: u64) -> (u64, u64) {
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
    })
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_are_set_as_linux_sets_them() {
        assert!(kept(r::RLIMIT_MEMLOCK) && kept(r::RLIMIT_NICE));
        assert!(!kept(r::RLIMIT_NOFILE) && !kept(r::RLIMIT_STACK));
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
