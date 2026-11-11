//! BSD process accounting (`acct`): while it is on, each process of the
//! pid namespace appends a record of itself (`struct acct_v3`) to the
//! accounting file as it ends.
//!
//! The file's host path is kept in a small file of fwe's, one per pid
//! namespace (beside the process records in the initial one, in the
//! namespace's record directory otherwise). An ending process's record
//! goes to the nearest namespace, its own or one above it, with
//! accounting on, as Linux's does: a failed `open` a namespace when none
//! is.

use fwe_abi::errno;
use std::sync::atomic::{AtomicBool, Ordering};

/// The process was forked and has not run a program since (`AFORK`).
static FORKED: AtomicBool = AtomicBool::new(false);

/// `ac_flag` bits.
const AFORK: u8 = 0x01;
const ACORE: u8 = 0x08;
const AXSIG: u8 = 0x10;
/// `ac_version`: `acct_v3`, little-endian.
const ACCT_V3: u8 = 3;
/// Linux's accounting clock (`AHZ`).
const AHZ: u64 = 100;

/// The file holding the accounting file's host path, for this process's
/// pid namespace.
fn setting() -> Option<std::ffi::CString> {
    let dir = match crate::pidns::current().first() {
        Some(ns) => ns.dir().to_vec(),
        None => crate::procreg::records_dir()?,
    };
    setting_in(&dir)
}

fn setting_in(dir: &[u8]) -> Option<std::ffi::CString> {
    std::ffi::CString::new([dir, b"/acct"].concat()).ok()
}

/// The accounting file a record of this process goes to: the nearest pid
/// namespace's, from its own up to the initial one, that has one.
fn target() -> Option<Vec<u8>> {
    let mut dirs: Vec<Vec<u8>> =
        crate::pidns::current().iter().map(|ns| ns.dir().to_vec()).collect();
    dirs.extend(crate::procreg::records_dir());
    dirs.iter().find_map(|d| {
        let p = setting_in(d)?;
        std::fs::read(<std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(p.as_bytes()))
            .ok()
    })
}

/// Turn accounting on, to the file at host path `host`, or off (`None`).
pub fn set(host: Option<&[u8]>) -> Result<(), i32> {
    let path = setting().ok_or(errno::ENOMEM)?;
    let p = <std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(path.as_bytes());
    match host {
        None => {
            let _ = std::fs::remove_file(p);
            Ok(())
        }
        Some(h) => {
            let tmp = [path.as_bytes(), b".new"].concat();
            let t = <std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(&tmp);
            std::fs::write(t, h).and_then(|()| std::fs::rename(t, p)).map_err(|_| errno::EIO)
        }
    }
}

/// This process is a fork child.
pub fn forked_child() {
    FORKED.store(true, Ordering::Relaxed);
}

/// This process runs another program.
pub fn exec() {
    FORKED.store(false, Ordering::Relaxed);
}

/// Linux's `comp_t`: a 13-bit mantissa and a base-8 exponent.
fn comp_t(mut value: u64) -> u16 {
    const MANT: u32 = 13;
    const MAXFRACT: u64 = (1 << MANT) - 1;
    let (mut exp, mut rnd) = (0u64, 0u64);
    while value > MAXFRACT {
        rnd = value & 4;
        value >>= 3;
        exp += 1;
    }
    if rnd != 0 {
        value += 1;
        if value > MAXFRACT {
            value >>= 3;
            exp += 1;
        }
    }
    if exp > 7 { u16::MAX } else { ((exp << MANT) + value) as u16 }
}

fn ticks(tv: libc::timeval) -> u64 {
    (tv.tv_sec as u64 * AHZ) + tv.tv_usec as u64 / (1_000_000 / AHZ)
}

/// This process ends with Linux wait status `status`: its record, if
/// accounting is on.
pub fn process_ending(status: i32) {
    let Some(file) = target() else { return };
    let Ok(target) = std::ffi::CString::new(file) else { return };
    let rec = record(status);
    // SAFETY: a NUL-terminated path; a 64-byte buffer; closed below.
    unsafe {
        let fd = libc::open(target.as_ptr(), libc::O_WRONLY | libc::O_APPEND | libc::O_CLOEXEC);
        if fd >= 0 {
            libc::write(fd, rec.as_ptr().cast(), rec.len());
            libc::close(fd);
        }
    }
}

/// This process's `struct acct_v3`.
fn record(status: i32) -> [u8; 64] {
    // SAFETY: getpid and getppid cannot fail.
    let (me, parent) = unsafe { (libc::getpid(), libc::getppid()) };
    let rec = crate::procreg::read(me);
    let ids = crate::procreg::ids(me);
    let start = rec.as_ref().map_or(0, |r| r.start);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_micros() as u64);
    // SAFETY: an all-zero rusage is a valid out-parameter.
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    let mut flag = 0u8;
    if FORKED.load(Ordering::Relaxed) {
        flag |= AFORK;
    }
    if status & 0x80 != 0 {
        flag |= ACORE;
    }
    if status & 0x7f != 0 {
        flag |= AXSIG;
    }
    let mut b = [0u8; 64];
    b[0] = flag;
    b[1] = ACCT_V3;
    // ac_tty (2..4): fwe gives processes no terminal number.
    b[4..8].copy_from_slice(&(status as u32).to_le_bytes());
    b[8..12].copy_from_slice(&ids[0].to_le_bytes());
    b[12..16].copy_from_slice(&ids[4].to_le_bytes());
    let g = crate::pidns::to_guest;
    b[16..20].copy_from_slice(&(g(me) as u32).to_le_bytes());
    b[20..24].copy_from_slice(&(g(parent) as u32).to_le_bytes());
    b[24..28].copy_from_slice(&((start / 1_000_000) as u32).to_le_bytes());
    let elapsed = now.saturating_sub(start) / (1_000_000 / AHZ);
    b[28..32].copy_from_slice(&(elapsed as f32).to_le_bytes());
    let comps = [
        ticks(ru.ru_utime),
        ticks(ru.ru_stime),
        // The most memory it held, in KiB (the host reports bytes).
        ru.ru_maxrss as u64 / 1024,
        0,
        0,
        ru.ru_minflt as u64,
        ru.ru_majflt as u64,
        0,
    ];
    for (i, v) in comps.into_iter().enumerate() {
        b[32 + 2 * i..34 + 2 * i].copy_from_slice(&comp_t(v).to_le_bytes());
    }
    if let Some(r) = rec {
        let n = r.comm.len().min(15);
        b[48..48 + n].copy_from_slice(&r.comm[..n]);
    }
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `comp_t` as Linux encodes it: exact below 8192, then rounded.
    #[test]
    fn comp_t_is_linuxs() {
        assert_eq!(comp_t(0), 0);
        assert_eq!(comp_t(8191), 8191);
        assert_eq!(comp_t(8192), (1 << 13) | 1024);
        assert_eq!(comp_t(8196), (1 << 13) | 1025);
        assert_eq!(comp_t(u64::MAX), u16::MAX);
    }
}
