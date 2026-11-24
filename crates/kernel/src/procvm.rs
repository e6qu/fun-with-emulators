//! `process_vm_readv` and `process_vm_writev`: another process's memory,
//! read or written without stopping it.
//!
//! Its memory is its own, so the caller writes the request (and, to write,
//! the data) to a host shared memory object both map (memory, not a file)
//! and asks the process through its signal mailbox
//! ([`crate::signote::request_mem`]); the process carries it out in its
//! wake handler, with the host's copies of its own task, which report an
//! address with nothing behind it rather than fault, and wakes the caller
//! on a reply socket. A tracee of the caller's stopped in a ptrace stop
//! serves only its tracer's requests: its memory goes through its ptrace
//! mailbox ([`crate::ptrace::tracee_memory`]). The caller's own memory is
//! copied directly.

use crate::{Kernel, Platform, uaccess};
use fwe_abi::{err, errno};

/// The most ranges either side may name (`UIO_MAXIOV`).
const MAX_RANGES: u64 = 1024;

/// A guest's `struct iovec` array at `at` of `count`: `EINVAL` for a
/// length past `ssize_t` in all.
fn ranges(at: u64, count: u64) -> Result<Vec<(u64, u64)>, i32> {
    if count == 0 {
        return Ok(Vec::new());
    }
    let b = uaccess::read_bytes(at, count as usize * 16)?;
    let v: Vec<(u64, u64)> = b
        .as_chunks::<16>()
        .0
        .iter()
        .map(|c| {
            (
                u64::from_ne_bytes(c[..8].try_into().unwrap()),
                u64::from_ne_bytes(c[8..].try_into().unwrap()),
            )
        })
        .collect();
    let mut total = 0u64;
    for &(_, len) in &v {
        total = total.checked_add(len).ok_or(errno::EINVAL)?;
    }
    if total > i64::MAX as u64 {
        return Err(errno::EINVAL);
    }
    Ok(v)
}

/// Copy between `local` ranges of the caller and the flat `data`: into
/// them (`into`), or out of them: the bytes copied, up to a fault.
fn scatter(local: &[(u64, u64)], data: &mut [u8], into: bool) -> u64 {
    let mut done = 0usize;
    for &(base, len) in local {
        if done == data.len() {
            break;
        }
        let n = (len as usize).min(data.len() - done);
        if n == 0 {
            continue;
        }
        let r = if into {
            uaccess::write_from(base, &data[done..done + n])
        } else {
            uaccess::read_into(base, &mut data[done..done + n])
        };
        if r.is_err() {
            break;
        }
        done += n;
    }
    done as u64
}

impl<P: Platform> Kernel<P> {
    /// `process_vm_readv(pid, local, liovcnt, remote, riovcnt, flags)`
    /// (`write` false) or `process_vm_writev`.
    pub(crate) fn sys_process_vm(&mut self, write: bool, a: [u64; 6]) -> i64 {
        let (pid, flags) = (a[0] as i32, a[5]);
        if flags != 0 || a[2] > MAX_RANGES || a[4] > MAX_RANGES {
            return err(errno::EINVAL);
        }
        let local = match ranges(a[1], a[2]) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        let remote = match ranges(a[3], a[4]) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        let Some(host) = crate::pidns::to_host(pid).filter(|&h| crate::host::probe(h).exists())
        else {
            return err(errno::ESRCH);
        };
        let me = crate::host::pid();
        // Only an fwe process can copy its own memory for the caller; any
        // other is one the caller may not attach to, as `ptrace` has it.
        if host != me && (!crate::host::is_fwe(host) || !self.may_trace(host)) {
            return err(errno::EPERM);
        }
        let total = local.iter().map(|r| r.1).sum::<u64>().min(remote.iter().map(|r| r.1).sum());
        if total == 0 {
            return 0;
        }
        // The data that moves, gathered from the side it comes from.
        let mut data = vec![0u8; total as usize];
        if write && scatter(&local, &mut data, false) < total {
            return err(errno::EFAULT);
        }
        let moved = if host == me {
            // This process's own memory, copied range by range.
            let mut done = 0usize;
            for &(base, len) in &remote {
                let n = (len as usize).min(data.len() - done);
                let r = if write {
                    uaccess::write_from(base, &data[done..done + n])
                } else {
                    uaccess::read_into(base, &mut data[done..done + n])
                };
                if r.is_err() {
                    break;
                }
                done += n;
                if done == data.len() {
                    break;
                }
            }
            if done == 0 { -i64::from(errno::EFAULT) } else { done as i64 }
        } else if crate::ptrace::traces_stopped(host.get()) {
            // A tracee of this process, stopped: its memory through its
            // mailbox, as its stop serves no other request.
            let mut done = 0usize;
            for &(base, len) in &remote {
                let n = (len as usize).min(data.len() - done);
                if n == 0 {
                    continue;
                }
                match crate::ptrace::tracee_memory(
                    host.get(),
                    base,
                    &mut data[done..done + n],
                    write,
                ) {
                    Ok(k) if k == n => done += k,
                    Ok(k) => {
                        done += k;
                        break;
                    }
                    Err(_) => break,
                }
                if done == data.len() {
                    break;
                }
            }
            if done == 0 { -i64::from(errno::EFAULT) } else { done as i64 }
        } else {
            match remote_copy(host, write, &remote, &mut data) {
                Ok(n) => n,
                Err(e) => return err(e),
            }
        };
        if moved < 0 {
            return moved;
        }
        if !write {
            // Nothing landed in the caller's memory: its fault.
            return match scatter(&local, &mut data[..moved as usize], true) {
                0 => err(errno::EFAULT),
                n => n as i64,
            };
        }
        moved
    }
}

/// Copy between process `host`'s memory at `addr` and `data` (into it if
/// `write`): the bytes moved.
pub fn remote(
    host: crate::ids::HostPid,
    addr: u64,
    data: &mut [u8],
    write: bool,
) -> Result<usize, i32> {
    let n = remote_copy(host, write, &[(addr, data.len() as u64)], data)?;
    Ok(n.max(0) as usize)
}

/// Have process `host` copy between its `remote` ranges and `data`: the
/// bytes moved (or `-EFAULT`).
#[cfg(target_os = "macos")]
fn remote_copy(
    host: crate::ids::HostPid,
    write: bool,
    remote: &[(u64, u64)],
    data: &mut [u8],
) -> Result<i64, i32> {
    use crate::signote::{MEM_HEADER, MEM_RETRY};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let reply = crate::signote::fd_reply_socket().ok_or(errno::EMFILE)?;
    let name = crate::signote::mem_name(crate::host::pid().get(), reply.token);
    // The ranges, cut to the data that moves.
    let mut left = data.len() as u64;
    let mut cut = Vec::new();
    for &(base, len) in remote {
        if left == 0 {
            break;
        }
        let n = len.min(left);
        cut.push((base, n));
        left -= n;
    }
    let data_at = MEM_HEADER + cut.len() * 16;
    let size = data_at + data.len();
    // The request, in a host shared memory object the process maps
    // (memory, not a file).
    // SAFETY: a NUL-terminated name; plain host calls.
    let fd = unsafe {
        libc::shm_open(
            name.as_ptr().cast(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(crate::host::errno_to_linux(crate::host::last_errno()));
    }
    // Out of the guest's descriptors (closed if there is no room).
    let fd = match crate::fdtable::reserve(fd) {
        Ok(fd) => fd,
        Err(e) => {
            // SAFETY: a NUL-terminated name.
            unsafe { libc::shm_unlink(name.as_ptr().cast()) };
            return Err(e);
        }
    };
    // SAFETY: a descriptor just made, owned here.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let result = (|| {
        // SAFETY: plain host calls on the object just made.
        let map = unsafe {
            if libc::ftruncate(fd.as_raw_fd(), size as libc::off_t) != 0 {
                return Err(errno::ENOMEM);
            }
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if map == libc::MAP_FAILED {
            return Err(errno::ENOMEM);
        }
        // SAFETY: the mapping just made, `size` bytes, unmapped below.
        let m = unsafe { std::slice::from_raw_parts_mut(map.cast::<u8>(), size) };
        m[..4].copy_from_slice(&u32::from(write).to_ne_bytes());
        m[4..8].copy_from_slice(&(cut.len() as u32).to_ne_bytes());
        for (i, (base, len)) in cut.iter().enumerate() {
            let at = MEM_HEADER + i * 16;
            m[at..at + 8].copy_from_slice(&base.to_ne_bytes());
            m[at + 8..at + 16].copy_from_slice(&len.to_ne_bytes());
        }
        if write {
            m[data_at..].copy_from_slice(data);
        }
        let r = (|| {
            for _ in 0..1000 {
                m[8..16].copy_from_slice(&0i64.to_ne_bytes());
                crate::signote::request_mem(host, reply.token)?;
                if crate::host::kill_process(host, crate::host::WAKE_SIGNAL) != 0 {
                    return Err(errno::ESRCH);
                }
                // Its answer, while it lives.
                loop {
                    let mut fds =
                        [libc::pollfd { fd: reply.sock, events: libc::POLLIN, revents: 0 }];
                    // SAFETY: one valid pollfd.
                    if unsafe { libc::poll(fds.as_mut_ptr(), 1, 100) } > 0 {
                        break;
                    }
                    if !crate::host::probe(host).exists() {
                        return Err(errno::ESRCH);
                    }
                    if crate::thread::deliverable() != 0 {
                        return Err(errno::EINTR);
                    }
                }
                crate::signote::receive_fd(reply.sock);
                let r = i64::from_ne_bytes(m[8..16].try_into().unwrap());
                if r == MEM_RETRY {
                    crate::procstore::Busy::new().sleep(std::time::Duration::from_millis(1));
                    continue;
                }
                if r > 0 && !write {
                    let n = (r as usize).min(data.len());
                    data[..n].copy_from_slice(&m[data_at..data_at + n]);
                }
                return Ok(r);
            }
            Err(errno::EAGAIN)
        })();
        // SAFETY: the mapping made above, no longer used.
        unsafe { libc::munmap(map, size) };
        r
    })();
    // SAFETY: a NUL-terminated name.
    unsafe { libc::shm_unlink(name.as_ptr().cast()) };
    result
}

#[cfg(not(target_os = "macos"))]
fn remote_copy(
    _: crate::ids::HostPid,
    _: bool,
    _: &[(u64, u64)],
    _: &mut [u8],
) -> Result<i64, i32> {
    Err(errno::ENOSYS)
}
