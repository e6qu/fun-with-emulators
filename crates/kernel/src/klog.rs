//! The kernel log: what `syslog(2)` (`dmesg`) reads, every fwe process's.
//!
//! fwe's kernel writes to it what Linux's writes there that a guest acts
//! on: the audit records of seccomp actions Linux logs
//! ([`crate::seccomp`]). A shared record ([`crate::shared`]) holds the
//! lines, each as Linux's `printk` makes it (`<level>[seconds.micros]
//! text`), up to Linux's buffer size, the oldest dropped first, and how
//! much of it a destructive read (`SYSLOG_ACTION_READ`) has taken.

use crate::shared::{Data, Record};
use crate::snapshot::{Dec, Enc};

/// The log's size (`CONFIG_LOG_BUF_SHIFT` of 17).
pub const LOG_BUF_LEN: usize = 1 << 17;

/// `KERN_NOTICE`, the level audit records are printed at.
pub const NOTICE: u8 = 5;

/// The log's text and how much of its end is still unread.
#[derive(Clone, Debug, Default)]
pub struct Log {
    pub text: Vec<u8>,
    pub unread: usize,
}

impl Data for Log {
    fn encode(&self, e: &mut Enc) {
        e.bytes(&self.text);
        e.u64(self.unread as u64);
    }
    fn decode(d: &mut Dec) -> Self {
        let text = d.bytes();
        let unread = (d.u64() as usize).min(text.len());
        Log { text, unread }
    }
}

fn record() -> Option<&'static Record<Log>> {
    static R: std::sync::OnceLock<Option<Record<Log>>> = std::sync::OnceLock::new();
    R.get_or_init(|| Record::named("klog", 0, Log::default).ok()).as_ref()
}

/// Append `text` to the log at `level`, stamped with the time since boot.
pub fn log(level: u8, text: &str) {
    let Some(r) = record() else { return };
    let up = crate::host::uptime();
    let line = format!("<{level}>[{:5}.{:06}] {text}\n", up as u64, (up.fract() * 1e6) as u64);
    let _ = r.update(|l| {
        l.text.extend_from_slice(line.as_bytes());
        l.unread += line.len();
        if l.text.len() > LOG_BUF_LEN {
            let drop = l.text.len() - LOG_BUF_LEN;
            // Whole lines go.
            let cut = l.text[drop..]
                .iter()
                .position(|&b| b == b'\n')
                .map_or(l.text.len(), |p| drop + p + 1);
            l.text.drain(..cut);
            l.unread = l.unread.min(l.text.len());
        }
        Ok(())
    });
}

/// The last `len` bytes of the log (whole of it if shorter), and with
/// `clear` the log emptied (`SYSLOG_ACTION_READ_ALL`, `READ_CLEAR`).
pub fn read_all(len: usize, clear: bool) -> Vec<u8> {
    let Some(r) = record() else { return Vec::new() };
    let l = r.get();
    let out = l.text[l.text.len().saturating_sub(len)..].to_vec();
    if clear {
        self::clear();
    }
    out
}

/// Up to `len` bytes of what no destructive read has taken, taken now
/// (`SYSLOG_ACTION_READ`).
pub fn read_unread(len: usize) -> Vec<u8> {
    let Some(r) = record() else { return Vec::new() };
    r.update(|l| {
        let start = l.text.len() - l.unread;
        let n = l.unread.min(len);
        l.unread -= n;
        Ok(l.text[start..start + n].to_vec())
    })
    .unwrap_or_default()
}

/// How much is unread (`SYSLOG_ACTION_SIZE_UNREAD`).
pub fn unread() -> usize {
    record().map_or(0, |r| r.get().unread)
}

/// Empty the log (`SYSLOG_ACTION_CLEAR`).
pub fn clear() {
    if let Some(r) = record() {
        let _ = r.update(|l| {
            *l = Log::default();
            Ok(())
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A line logged is read back whole, as `printk` frames it.
    #[test]
    fn lines_are_read_back() {
        let tag = format!("fwe-klog-test-{}", std::process::id());
        log(NOTICE, &tag);
        let all = String::from_utf8(read_all(LOG_BUF_LEN, false)).unwrap();
        let line = all.lines().find(|l| l.ends_with(&tag)).unwrap();
        assert!(line.starts_with("<5>["), "{line}");
    }
}
