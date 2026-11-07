//! Writes to the files of fwe's whose writes act rather than store: a
//! cgroup's interface files ([`crate::cgroupfs`]), the user-namespace maps
//! of `/proc/<pid>` ([`crate::userns`]), a namespace's sysctls
//! ([`crate::sysctl`]) and `/proc/<pid>/oom_score_adj`
//! ([`crate::procpid`]). On Linux each takes one write's bytes, whichever
//! call makes it (`write`, `writev`, `pwrite64`, `pwritev`, `pwritev2`; C
//! libraries' buffered output uses `writev`), so every one of those comes
//! here first.

use crate::fdmarks::{self, Mark};
use crate::uaccess;
use fwe_abi::err;

/// Where one write's bytes are.
pub enum Source<'a> {
    /// At this guest address.
    Guest(u64),
    /// In these host buffers, checked (a vectored write's).
    Host(&'a [libc::iovec]),
}

/// The most of one write taken: more than any of these files holds.
const MOST: usize = 1 << 16;

/// Whether `fd` is one of these files.
pub fn is(fd: i32) -> bool {
    fdmarks::cgroup_file(fd).is_some()
        || (fdmarks::any_marks()
            && matches!(
                fdmarks::marked(fd),
                Some(Mark::Sysctl(_) | Mark::ProcMap { .. } | Mark::OomScore { .. })
            ))
}

/// A write of `len` bytes from `src` to `fd`: if `fd` is one of these
/// files, what the write does (`Some` result).
pub fn write(fd: i32, src: Source, len: u64) -> Option<i64> {
    if !is(fd) {
        return None;
    }
    let data = match src {
        Source::Guest(buf) => match uaccess::read_bytes(buf, (len as usize).min(MOST)) {
            Ok(d) => d,
            Err(e) => return Some(err(e)),
        },
        Source::Host(iov) => {
            let mut d = Vec::new();
            // An empty buffer may be at any address, null included.
            for v in iov.iter().filter(|v| v.iov_len > 0) {
                let take = v.iov_len.min(MOST - d.len());
                // SAFETY: the buffers are the guest's, checked by the caller.
                d.extend_from_slice(unsafe {
                    std::slice::from_raw_parts(v.iov_base.cast::<u8>(), take)
                });
            }
            d
        }
    };
    crate::cgroupfs::try_write(fd, &data, len)
        .or_else(|| crate::userns::try_write(fd, &data, len))
        .or_else(|| crate::sysctl::try_write(fd, &data, len))
        .or_else(|| crate::procpid::try_write(fd, &data, len))
}

/// The bytes in all of host buffers `iov`.
pub fn total(iov: &[libc::iovec]) -> u64 {
    iov.iter().fold(0u64, |t, v| t.saturating_add(v.iov_len as u64))
}
