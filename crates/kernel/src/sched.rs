//! Scheduling policies: `sched_setscheduler`, `sched_getscheduler`,
//! `sched_setparam`, `sched_getparam`, `sched_setattr`, `sched_getattr`,
//! `sched_get_priority_max`, `sched_get_priority_min` and
//! `sched_rr_get_interval`.
//!
//! Each process's policy and attributes are kept in its record
//! ([`crate::procreg::Sched`]), set with Linux's checks (a real-time or
//! deadline policy, or another user's process, takes `CAP_SYS_NICE` or
//! what `RLIMIT_RTPRIO` and `RLIMIT_NICE` allow), read back, and inherited
//! by its children, as Linux keeps a task's. The host schedules the
//! process as it does any: a policy changes what is reported, not how the
//! process runs. Linux keeps them per thread; fwe per process.

use crate::procreg::Sched;
use crate::{Kernel, Platform, uaccess};
use fwe_abi::sched::*;
use fwe_abi::{err, errno, resource};

/// `SCHED_DEADLINE`'s smallest runtime (`1 << DL_SCALE` ns) and its
/// period's bounds (`kernel.sched_deadline_period_{min,max}_us`).
const DL_MIN_RUNTIME: u64 = 1 << 10;
const DL_PERIOD_MIN: u64 = 100 * 1000;
const DL_PERIOD_MAX: u64 = (1 << 22) * 1000;
/// The utilisation clamps' scale.
const CAPACITY: u32 = 1024;
/// `SCHED_RR`'s time slice (Linux's 100 ms).
const RR_SLICE_NS: i64 = 100_000_000;

fn valid_policy(p: u32) -> bool {
    matches!(p, SCHED_OTHER | SCHED_FIFO | SCHED_RR | SCHED_BATCH | SCHED_IDLE | SCHED_DEADLINE)
}

fn rt(p: u32) -> bool {
    matches!(p, SCHED_FIFO | SCHED_RR)
}

fn fair(p: u32) -> bool {
    matches!(p, SCHED_OTHER | SCHED_BATCH)
}

/// Linux's `__checkparam_dl`: a deadline policy's parameters.
fn valid_deadline(runtime: u64, deadline: u64, period: u64) -> bool {
    if deadline == 0 || runtime < DL_MIN_RUNTIME {
        return false;
    }
    if deadline & (1 << 63) != 0 || period & (1 << 63) != 0 {
        return false;
    }
    let period = if period == 0 { deadline } else { period };
    period >= deadline && deadline >= runtime && (DL_PERIOD_MIN..=DL_PERIOD_MAX).contains(&period)
}

/// What a set asks for: a policy (`None`: keep the current one), its
/// attributes, a nice value (`None`: keep it) and the setattr flags.
struct Request {
    policy: Option<u32>,
    reset_on_fork: Option<bool>,
    priority: u32,
    nice: Option<i32>,
    runtime: u64,
    deadline: u64,
    period: u64,
    flags: u64,
    util_min: Option<u32>,
    util_max: Option<u32>,
}

impl<P: Platform> Kernel<P> {
    /// The host process `pid` names (0: the caller; an `int`, its upper
    /// half not the guest's): `EINVAL` for a negative one, `ESRCH` for one
    /// that is not there. A host process fwe did not start counts, as an
    /// ordinary one that fwe cannot change.
    fn sched_target(&self, pid: u64) -> Result<i32, i32> {
        let pid = pid as i32;
        if pid < 0 {
            return Err(errno::EINVAL);
        }
        // SAFETY: getpid cannot fail.
        let me = unsafe { libc::getpid() };
        if pid == 0 || pid == crate::thread::tgid() || crate::thread::tids().contains(&pid) {
            return Ok(me);
        }
        let host = crate::pidns::to_host(pid).ok_or(errno::ESRCH)?;
        // SAFETY: signal 0 only checks the process exists.
        let exists =
            unsafe { libc::kill(host, 0) } == 0 || crate::host::last_errno() == libc::EPERM;
        if crate::procreg::read(host).is_none() && !exists {
            return Err(errno::ESRCH);
        }
        Ok(host)
    }

    /// Process `host`'s attributes (an ordinary process's for one without
    /// a record).
    fn sched_of(&self, host: i32) -> Sched {
        crate::procreg::sched(host).unwrap_or_default()
    }

    /// Whether the caller may change process `host`'s scheduling from `cur`
    /// (nice value `nice_now`) as asked, by Linux's rules for a caller
    /// without `CAP_SYS_NICE`.
    fn sched_allowed(
        &self,
        host: i32,
        cur: &Sched,
        nice_now: i32,
        policy: u32,
        req: &Request,
    ) -> bool {
        if self.creds.has(crate::caps::CAP_SYS_NICE) {
            return true;
        }
        let limit = |res| crate::syscalls::own_limit_of(res);
        // `RLIMIT_NICE` bounds the least nice value as 20 less it.
        let nice_ok = |nice: i32| (20 - nice) as u64 <= limit(resource::RLIMIT_NICE);
        if fair(policy) && req.nice.is_some_and(|n| n < nice_now && !nice_ok(n)) {
            return false;
        }
        if rt(policy) {
            let rtprio = limit(resource::RLIMIT_RTPRIO);
            if policy != cur.policy && rtprio == 0 {
                return false;
            }
            if req.priority > cur.priority && req.priority as u64 > rtprio {
                return false;
            }
        }
        if policy == SCHED_DEADLINE {
            return false;
        }
        if cur.policy == SCHED_IDLE && policy != SCHED_IDLE && !nice_ok(nice_now) {
            return false;
        }
        // SAFETY: getpid cannot fail.
        let me = unsafe { libc::getpid() };
        let owner = if host == me {
            [self.creds.uid, self.creds.euid]
        } else {
            let i = crate::procreg::ids(host);
            [i[0], i[1]]
        };
        if !owner.contains(&self.creds.euid) {
            return false;
        }
        !(cur.reset_on_fork && req.reset_on_fork == Some(false))
    }

    /// What process `host`'s scheduling, `cur` with nice value `nice`,
    /// becomes as `req` asks, in Linux's order: the policy and its
    /// parameters (`EINVAL`), the caller's right (`EPERM`), then the
    /// utilisation clamps (`EINVAL`).
    fn sched_apply(
        &self,
        host: i32,
        cur: &Sched,
        nice: i32,
        req: &Request,
    ) -> Result<(Sched, i32), i32> {
        let policy = req.policy.unwrap_or(cur.policy);
        if !valid_policy(policy) {
            return Err(errno::EINVAL);
        }
        if req.flags & !SCHED_FLAG_ALL != 0 || req.priority > MAX_RT_PRIO {
            return Err(errno::EINVAL);
        }
        if (policy == SCHED_DEADLINE && !valid_deadline(req.runtime, req.deadline, req.period))
            || rt(policy) != (req.priority != 0)
        {
            return Err(errno::EINVAL);
        }
        if !self.sched_allowed(host, cur, nice, policy, req) {
            return Err(errno::EPERM);
        }
        let clamp_ok = |v: Option<u32>| v.is_none_or(|v| v <= CAPACITY || v == u32::MAX);
        if !clamp_ok(req.util_min) || !clamp_ok(req.util_max) {
            return Err(errno::EINVAL);
        }
        let util_min = req.util_min.map_or(cur.util_min, |v| (v != u32::MAX).then_some(v));
        let util_max = req.util_max.map_or(cur.util_max, |v| (v != u32::MAX).then_some(v));
        if util_min.unwrap_or(0) > util_max.unwrap_or(CAPACITY) {
            return Err(errno::EINVAL);
        }
        let new = Sched {
            policy,
            priority: if rt(policy) { req.priority } else { 0 },
            reset_on_fork: req.reset_on_fork.unwrap_or(cur.reset_on_fork),
            runtime: if policy == SCHED_DEADLINE { req.runtime } else { 0 },
            deadline: if policy == SCHED_DEADLINE { req.deadline } else { 0 },
            period: if policy == SCHED_DEADLINE { req.period } else { 0 },
            util_min,
            util_max,
        };
        let nice = match req.nice.filter(|_| fair(policy)) {
            Some(n) => n.clamp(-20, 19),
            None => nice,
        };
        Ok((new, nice))
    }

    /// Set process `host`'s scheduling as `req` asks, under its record's
    /// lock. A host process fwe did not start is the host's to schedule:
    /// checked, then `EPERM`.
    fn sched_set(&mut self, host: i32, req: Request) -> Result<(), i32> {
        if crate::procreg::read(host).is_none() {
            let nice = crate::procreg::nice(host);
            self.sched_apply(host, &Sched::default(), nice, &req)?;
            return Err(errno::EPERM);
        }
        crate::procreg::change_sched(host, |cur, nice| self.sched_apply(host, cur, nice, &req))
    }

    /// `sched_setscheduler(pid, policy, param)` (`policy` `None`:
    /// `sched_setparam`).
    pub(crate) fn sys_sched_setscheduler(
        &mut self,
        pid: u64,
        policy: Option<u64>,
        param: u64,
    ) -> i64 {
        let r = (|| {
            if param == 0 || (pid as i32) < 0 {
                return Err(errno::EINVAL);
            }
            let priority: i32 = uaccess::read(param)?;
            let host = self.sched_target(pid)?;
            let (policy, reset_on_fork) = match policy {
                None => (None, None),
                Some(p) => {
                    let p = p as i32;
                    if p < 0 {
                        return Err(errno::EINVAL);
                    }
                    let p = p as u32;
                    (Some(p & !SCHED_RESET_ON_FORK), Some(p & SCHED_RESET_ON_FORK != 0))
                }
            };
            if priority < 0 {
                return Err(errno::EINVAL);
            }
            let cur = self.sched_of(host);
            let req = Request {
                policy,
                reset_on_fork,
                priority: priority as u32,
                nice: None,
                runtime: cur.runtime,
                deadline: cur.deadline,
                period: cur.period,
                flags: 0,
                util_min: None,
                util_max: None,
            };
            self.sched_set(host, req)
        })();
        match r {
            Ok(()) => 0,
            Err(e) => err(e),
        }
    }

    /// `sched_getscheduler(pid)`.
    pub(crate) fn sys_sched_getscheduler(&mut self, pid: u64) -> i64 {
        match self.sched_target(pid) {
            Ok(host) => {
                let s = self.sched_of(host);
                (s.policy | if s.reset_on_fork { SCHED_RESET_ON_FORK } else { 0 }) as i64
            }
            Err(e) => err(e),
        }
    }

    /// `sched_getparam(pid, param)`.
    pub(crate) fn sys_sched_getparam(&mut self, pid: u64, param: u64) -> i64 {
        if param == 0 || (pid as i32) < 0 {
            return err(errno::EINVAL);
        }
        match self.sched_target(pid) {
            Ok(host) => match uaccess::write(param, self.sched_of(host).priority as i32) {
                Ok(()) => 0,
                Err(e) => err(e),
            },
            Err(e) => err(e),
        }
    }

    /// `sched_rr_get_interval(pid, tp)`: a round-robin process's time
    /// slice; none for the others (a fair process's is under a tick).
    pub(crate) fn sys_sched_rr_get_interval(&mut self, pid: u64, tp: u64) -> i64 {
        let host = match self.sched_target(pid) {
            Ok(h) => h,
            Err(e) => return err(e),
        };
        let ns = if self.sched_of(host).policy == SCHED_RR { RR_SLICE_NS } else { 0 };
        match uaccess::write(tp, [ns / 1_000_000_000, ns % 1_000_000_000]) {
            Ok(()) => 0,
            Err(e) => err(e),
        }
    }

    /// `sched_setattr(pid, attr, flags)`.
    pub(crate) fn sys_sched_setattr(&mut self, pid: u64, attr: u64, flags: u64) -> i64 {
        let r = (|| {
            if attr == 0 || (pid as i32) < 0 || flags != 0 {
                return Err(errno::EINVAL);
            }
            // The size the caller gave, checked as Linux checks it: past
            // what fwe knows, only zeros (`E2BIG`, with fwe's size written).
            let mut size: u32 = uaccess::read(attr)?;
            if size == 0 {
                size = ATTR_SIZE_VER0 as u32;
            }
            let too_big = || -> Result<(), i32> {
                let _ = uaccess::write(attr, ATTR_SIZE_VER1 as u32);
                Err(errno::E2BIG)
            };
            if (size as usize) < ATTR_SIZE_VER0 || size > 4096 {
                return too_big();
            }
            let raw = uaccess::read_bytes(attr, size as usize)?;
            if raw.len() > ATTR_SIZE_VER1 && raw[ATTR_SIZE_VER1..].iter().any(|&b| b != 0) {
                return too_big();
            }
            let mut a = [0u8; ATTR_SIZE_VER1];
            let n = raw.len().min(ATTR_SIZE_VER1);
            a[..n].copy_from_slice(&raw[..n]);
            let u32_at = |at: usize| u32::from_le_bytes(a[at..at + 4].try_into().unwrap());
            let u64_at = |at: usize| u64::from_le_bytes(a[at..at + 8].try_into().unwrap());
            let sflags = u64_at(8);
            let clamps = sflags & (SCHED_FLAG_UTIL_CLAMP_MIN | SCHED_FLAG_UTIL_CLAMP_MAX);
            if clamps != 0 && (size as usize) < ATTR_SIZE_VER1 {
                return Err(errno::EINVAL);
            }
            let policy = u32_at(4);
            if (policy as i32) < 0 {
                return Err(errno::EINVAL);
            }
            let host = self.sched_target(pid)?;
            let cur = self.sched_of(host);
            let keep_params = sflags & SCHED_FLAG_KEEP_PARAMS != 0;
            let req = Request {
                policy: (sflags & SCHED_FLAG_KEEP_POLICY == 0).then_some(policy),
                // Kept with the policy, as Linux keeps it.
                reset_on_fork: (sflags & SCHED_FLAG_KEEP_POLICY == 0)
                    .then_some(sflags & SCHED_FLAG_RESET_ON_FORK != 0),
                priority: if keep_params { cur.priority } else { u32_at(20) },
                nice: if keep_params {
                    Some(crate::procreg::nice(host))
                } else {
                    Some((u32_at(16) as i32).clamp(-20, 19))
                },
                runtime: if keep_params { cur.runtime } else { u64_at(24) },
                deadline: if keep_params { cur.deadline } else { u64_at(32) },
                period: if keep_params { cur.period } else { u64_at(40) },
                flags: sflags,
                util_min: (sflags & SCHED_FLAG_UTIL_CLAMP_MIN != 0).then_some(u32_at(48)),
                util_max: (sflags & SCHED_FLAG_UTIL_CLAMP_MAX != 0).then_some(u32_at(52)),
            };
            self.sched_set(host, req)
        })();
        match r {
            Ok(()) => 0,
            Err(e) => err(e),
        }
    }

    /// `sched_getattr(pid, attr, size, flags)`.
    pub(crate) fn sys_sched_getattr(&mut self, pid: u64, attr: u64, size: u64, flags: u64) -> i64 {
        if attr == 0
            || (pid as i32) < 0
            || size > 4096
            || (size as usize) < ATTR_SIZE_VER0
            || flags != 0
        {
            return err(errno::EINVAL);
        }
        let host = match self.sched_target(pid) {
            Ok(h) => h,
            Err(e) => return err(e),
        };
        let s = self.sched_of(host);
        let n = (size as usize).min(ATTR_SIZE_VER1);
        let mut a = [0u8; ATTR_SIZE_VER1];
        let mut put32 = |at: usize, v: u32| a[at..at + 4].copy_from_slice(&v.to_le_bytes());
        put32(0, n as u32);
        put32(4, s.policy);
        // A real-time or deadline process has a priority or parameters; any
        // other, its nice value.
        let timed = rt(s.policy) || s.policy == SCHED_DEADLINE;
        put32(16, if timed { 0 } else { crate::procreg::nice(host) as u32 });
        put32(20, s.priority);
        put32(48, s.util_min.unwrap_or(0));
        put32(52, s.util_max.unwrap_or(CAPACITY));
        let flags = if s.reset_on_fork { SCHED_FLAG_RESET_ON_FORK } else { 0 };
        a[8..16].copy_from_slice(&flags.to_le_bytes());
        a[24..32].copy_from_slice(&s.runtime.to_le_bytes());
        a[32..40].copy_from_slice(&s.deadline.to_le_bytes());
        a[40..48].copy_from_slice(&s.period.to_le_bytes());
        match uaccess::write_from(attr, &a[..n]) {
            Ok(()) => 0,
            Err(e) => err(e),
        }
    }
}

/// `sched_get_priority_max(policy)` (`max`) and `sched_get_priority_min`.
pub fn priority_bound(policy: u64, max: bool) -> i64 {
    let p = policy as i32;
    if p < 0 || !valid_policy(p as u32) {
        return err(errno::EINVAL);
    }
    match (rt(p as u32), max) {
        (true, true) => MAX_RT_PRIO as i64,
        (true, false) => 1,
        (false, _) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_ranges() {
        assert_eq!(priority_bound(SCHED_FIFO as u64, true), 99);
        assert_eq!(priority_bound(SCHED_RR as u64, false), 1);
        assert_eq!(priority_bound(SCHED_OTHER as u64, true), 0);
        assert_eq!(priority_bound(SCHED_DEADLINE as u64, false), 0);
        assert_eq!(priority_bound(4, true), err(errno::EINVAL));
        assert_eq!(priority_bound(u64::MAX, true), err(errno::EINVAL));
    }

    #[test]
    fn deadline_parameters() {
        let ms = 1_000_000;
        assert!(valid_deadline(10 * ms, 30 * ms, 30 * ms));
        assert!(valid_deadline(10 * ms, 30 * ms, 0));
        assert!(!valid_deadline(10 * ms, 0, 30 * ms));
        assert!(!valid_deadline(40 * ms, 30 * ms, 30 * ms));
        assert!(!valid_deadline(100, 30 * ms, 30 * ms));
        assert!(!valid_deadline(10 * ms, 30 * ms, 20 * ms));
        assert!(!valid_deadline(10_000, 50_000, 50_000));
    }
}
