//! Setting and adjusting the clocks: `clock_settime`, `settimeofday`,
//! `adjtimex` and `clock_adjtime`.
//!
//! The real-time clock is the host's, which fwe does not set: its
//! processes never hold `CAP_SYS_TIME` ([`crate::caps::INITIAL`]), as in a
//! container, so each call checks its arguments as Linux does and then
//! refuses a change with `EPERM`. Reading the clock's state (`adjtimex`
//! with no modes) reports it as Linux reports a clock nothing keeps in
//! sync.

use crate::{Kernel, Platform, uaccess};
use fwe_abi::clock::*;
use fwe_abi::{err, errno};

/// `struct __kernel_timex`: 208 bytes, `modes` at 0, `status` at 40, the
/// time (`tv_sec`, `tv_usec`) at 72 and `tick` at 88.
const TIMEX_SIZE: usize = 208;

/// `ADJ_*` modes: the kernel's own split of the single-shot ones.
const ADJ_ADJTIME: u32 = 0x8000;
const ADJ_OFFSET_SINGLESHOT: u32 = 0x0001;
const ADJ_OFFSET_READONLY: u32 = 0x2000;

/// `STA_UNSYNC`, and `TIME_ERROR`, what a clock nothing keeps in sync
/// reports.
const STA_UNSYNC: i32 = 0x40;
const TIME_ERROR: i64 = 5;

/// `USER_HZ`: `tick` is in microseconds per tick of it.
const USER_HZ: i64 = 100;

/// Whether `id` is a clock Linux has (the CPU-time clocks aside).
fn known(id: u64) -> bool {
    matches!(
        id,
        CLOCK_REALTIME
            | CLOCK_MONOTONIC
            | CLOCK_PROCESS_CPUTIME_ID
            | CLOCK_THREAD_CPUTIME_ID
            | CLOCK_MONOTONIC_RAW
            | CLOCK_REALTIME_COARSE
            | CLOCK_MONOTONIC_COARSE
            | CLOCK_BOOTTIME
            | CLOCK_REALTIME_ALARM
            | CLOCK_BOOTTIME_ALARM
            | CLOCK_TAI
    )
}

/// What `timespec64_valid_settod` allows: a time the clock can be set to.
fn valid_settod(sec: i64, nsec: i64) -> bool {
    /// `KTIME_SEC_MAX` less Linux's 30-year margin.
    const MAX: i64 = i64::MAX / 1_000_000_000 - 30 * 365 * 86_400;
    (0..1_000_000_000).contains(&nsec) && (0..MAX).contains(&sec)
}

/// The clock's state as `adjtimex` reads it into the `struct timex` at
/// `buf`: unsynchronised, with the time now.
fn read_state(buf: &mut [u8]) -> i64 {
    let mut tv = libc::timeval { tv_sec: 0, tv_usec: 0 };
    // SAFETY: a valid out-parameter.
    unsafe { libc::gettimeofday(&mut tv, std::ptr::null_mut()) };
    let mut put = |at: usize, v: i64| buf[at..at + 8].copy_from_slice(&v.to_le_bytes());
    put(8, 0); // offset
    put(16, 0); // freq
    put(24, 16_000_000); // maxerror: NTP_PHASE_LIMIT
    put(32, 16_000_000); // esterror
    put(48, 2); // constant
    put(56, 1); // precision
    put(64, 500 << 16); // tolerance: 500 ppm, scaled
    put(72, tv.tv_sec);
    put(80, crate::host::usec(tv));
    put(88, 1_000_000 / USER_HZ); // tick
    for at in (96..112).step_by(8).chain((120..160).step_by(8)) {
        put(at, 0);
    }
    buf[40..44].copy_from_slice(&STA_UNSYNC.to_le_bytes());
    buf[112..116].fill(0); // shift
    buf[160..164].fill(0); // tai
    TIME_ERROR
}

/// `adjtimex` of the real-time clock with the `struct timex` at `p`.
fn adjtimex(p: u64) -> i64 {
    let mut buf = match uaccess::read_bytes(p, TIMEX_SIZE) {
        Ok(b) => b,
        Err(e) => return err(e),
    };
    let modes = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    // In Linux's order: a single-shot adjustment alone, and a change only
    // with `CAP_SYS_TIME`, which fwe's processes lack.
    if modes & ADJ_ADJTIME != 0 {
        if modes & ADJ_OFFSET_SINGLESHOT == 0 {
            return err(errno::EINVAL);
        }
        if modes & ADJ_OFFSET_READONLY == 0 {
            return err(errno::EPERM);
        }
    } else if modes != 0 {
        return err(errno::EPERM);
    }
    let state = read_state(&mut buf);
    match uaccess::write_from(p, &buf) {
        Ok(()) => state,
        Err(e) => err(e),
    }
}

impl<P: Platform> Kernel<P> {
    /// `clock_settime(id, tp)`.
    pub(crate) fn sys_clock_settime(&mut self, id: u64, tp: u64) -> i64 {
        // A CPU-time clock is never set; one that names nothing is
        // `EINVAL` (or `ESRCH`) first.
        if let Some(r) = crate::syscalls::cpu_clock_ns(id) {
            return err(r.err().unwrap_or(errno::EPERM));
        }
        if id != CLOCK_REALTIME {
            return err(errno::EINVAL);
        }
        let [sec, nsec]: [i64; 2] = match uaccess::read(tp) {
            Ok(t) => t,
            Err(e) => return err(e),
        };
        if !valid_settod(sec, nsec) {
            return err(errno::EINVAL);
        }
        err(errno::EPERM)
    }

    /// `settimeofday(tv, tz)`.
    pub(crate) fn sys_settimeofday(&mut self, tv: u64, tz: u64) -> i64 {
        if tv != 0 {
            let [sec, usec]: [i64; 2] = match uaccess::read(tv) {
                Ok(t) => t,
                Err(e) => return err(e),
            };
            if !(0..1_000_000).contains(&usec) || !valid_settod(sec, usec * 1000) {
                return err(errno::EINVAL);
            }
        }
        if tz != 0
            && let Err(e) = uaccess::read::<[i32; 2]>(tz)
        {
            return err(e);
        }
        err(errno::EPERM)
    }

    /// `adjtimex(buf)`.
    pub(crate) fn sys_adjtimex(&mut self, buf: u64) -> i64 {
        adjtimex(buf)
    }

    /// `clock_adjtime(id, buf)`: the real-time clock's `adjtimex`; the
    /// others cannot be adjusted.
    pub(crate) fn sys_clock_adjtime(&mut self, id: u64, buf: u64) -> i64 {
        if let Some(r) = crate::syscalls::cpu_clock_ns(id) {
            return err(r.err().unwrap_or(errno::EOPNOTSUPP));
        }
        if !known(id) {
            return err(errno::EINVAL);
        }
        if id != CLOCK_REALTIME {
            return err(errno::EOPNOTSUPP);
        }
        adjtimex(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_the_clock_may_be_set_to() {
        assert!(valid_settod(0, 0));
        assert!(valid_settod(1_700_000_000, 999_999_999));
        assert!(!valid_settod(-1, 0));
        assert!(!valid_settod(0, 1_000_000_000));
        assert!(!valid_settod(i64::MAX / 1_000_000_000, 0));
    }

    #[test]
    fn the_state_read_is_unsynchronised_with_the_time_now() {
        let mut buf = vec![0xffu8; TIMEX_SIZE];
        assert_eq!(read_state(&mut buf), TIME_ERROR);
        assert_eq!(i32::from_le_bytes(buf[40..44].try_into().unwrap()), STA_UNSYNC);
        assert_eq!(i64::from_le_bytes(buf[88..96].try_into().unwrap()), 10_000);
        assert!(i64::from_le_bytes(buf[72..80].try_into().unwrap()) > 1_700_000_000);
    }
}
