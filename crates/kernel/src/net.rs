//! Sockets.
//!
//! On Linux the socket calls pass straight through to the host kernel, whose
//! ABI the guest already speaks. On macOS the BSD socket API is close but not
//! identical, so this module translates:
//!
//! - **address families:** `AF_INET6` is 10 on Linux, 30 on macOS; `AF_INET`
//!   and `AF_UNIX` match.
//! - **`sockaddr` layout:** Linux leads with a 2-byte `sa_family`; macOS leads
//!   with a 1-byte `sa_len` and a 1-byte `sa_family`. The rest (port, address)
//!   is identical, so translation is a small header fix-up.
//! - **socket type flags:** Linux packs `SOCK_NONBLOCK`/`SOCK_CLOEXEC` into the
//!   `type` argument; macOS has no such bits, so they are stripped and applied
//!   with `fcntl` afterwards.
//! - **`setsockopt` names:** `SOL_SOCKET` is 1 on Linux, `0xffff` on macOS, and
//!   the option numbers differ; a table maps the common ones.
//! - **`send`/`recv` flags:** mostly reordered bits, mapped individually.
//!   `MSG_NOSIGNAL` has no macOS equivalent, so every socket gets
//!   `SO_NOSIGPIPE` instead (a broken pipe yields `EPIPE`, not a signal).
//!
//! Only `AF_INET`, `AF_INET6` and unnamed `AF_UNIX` (`socketpair`) are handled;
//! pathed `AF_UNIX` and `SCM_RIGHTS` ancillary data are not yet translated.
//!
//! The calls that can block — `connect`, `accept`, `recvfrom`, `recvmsg`,
//! `sendto`, `sendmsg` — run outside the kernel lock via `blocking_syscall`, so
//! a thread blocked in `accept`/`recv` never stalls the threads meant to feed
//! it.

use crate::host::ret;

/// `socket(domain, type, protocol)`.
///
/// # Safety
/// No pointer arguments.
pub unsafe fn socket(domain: u64, type_: u64, protocol: u64) -> i64 {
    #[cfg(target_os = "linux")]
    // SAFETY: plain host syscall.
    unsafe {
        ret(libc::socket(domain as i32, type_ as i32, protocol as i32) as i64)
    }
    #[cfg(not(target_os = "linux"))]
    // SAFETY: no pointers.
    unsafe {
        imp::socket(domain, type_, protocol)
    }
}

/// `socketpair(domain, type, protocol, sv)`.
///
/// # Safety
/// `sv` must point to two writable `i32`s.
pub unsafe fn socketpair(domain: u64, type_: u64, protocol: u64, sv: u64) -> i64 {
    #[cfg(target_os = "linux")]
    // SAFETY: the host validates the `sv` array.
    unsafe {
        ret(libc::socketpair(domain as i32, type_ as i32, protocol as i32, sv as *mut i32) as i64)
    }
    #[cfg(not(target_os = "linux"))]
    // SAFETY: the caller guarantees `sv` is writable for two i32s.
    unsafe {
        imp::socketpair(domain, type_, protocol, sv)
    }
}

/// `bind(fd, addr, addrlen)`.
///
/// # Safety
/// `addr` must point to `addrlen` readable bytes.
pub unsafe fn bind(fd: u64, addr: u64, addrlen: u64) -> i64 {
    #[cfg(target_os = "linux")]
    // SAFETY: the host validates the sockaddr.
    unsafe {
        ret(libc::bind(fd as i32, addr as *const libc::sockaddr, addrlen as libc::socklen_t) as i64)
    }
    #[cfg(not(target_os = "linux"))]
    // SAFETY: the caller guarantees the sockaddr spans addrlen.
    unsafe {
        imp::bind(fd, addr, addrlen)
    }
}

/// `listen(fd, backlog)`.
///
/// # Safety
/// No pointer arguments.
pub unsafe fn listen(fd: u64, backlog: u64) -> i64 {
    // SAFETY: plain host call on both platforms.
    unsafe { ret(libc::listen(fd as i32, backlog as i32) as i64) }
}

/// `connect(fd, addr, addrlen)`.
///
/// # Safety
/// `addr` must point to `addrlen` readable bytes.
pub unsafe fn connect(fd: u64, addr: u64, addrlen: u64) -> i64 {
    #[cfg(target_os = "linux")]
    // SAFETY: the host validates the sockaddr.
    unsafe {
        ret(libc::connect(fd as i32, addr as *const libc::sockaddr, addrlen as libc::socklen_t)
            as i64)
    }
    #[cfg(not(target_os = "linux"))]
    // SAFETY: the caller guarantees the sockaddr spans addrlen.
    unsafe {
        imp::connect(fd, addr, addrlen)
    }
}

/// `accept4(fd, addr, addrlen, flags)`; `accept` is this with `flags == 0`.
///
/// # Safety
/// `addr`/`addrlen`, if non-null, must be writable for a `sockaddr` and its
/// length.
pub unsafe fn accept4(fd: u64, addr: u64, addrlen: u64, flags: u64) -> i64 {
    #[cfg(target_os = "linux")]
    // SAFETY: the host validates the out pointers.
    unsafe {
        ret(libc::accept4(
            fd as i32,
            addr as *mut libc::sockaddr,
            addrlen as *mut libc::socklen_t,
            flags as i32,
        ) as i64)
    }
    #[cfg(not(target_os = "linux"))]
    // SAFETY: the caller guarantees the out pointers.
    unsafe {
        imp::accept4(fd, addr, addrlen, flags)
    }
}

/// `getsockname`/`getpeername` share this shape; `peer` selects which.
///
/// # Safety
/// `addr`/`addrlen` must be writable for a `sockaddr` and its length.
pub unsafe fn getname(fd: u64, addr: u64, addrlen: u64, peer: bool) -> i64 {
    #[cfg(target_os = "linux")]
    // SAFETY: the host validates the out pointers.
    unsafe {
        let a = addr as *mut libc::sockaddr;
        let l = addrlen as *mut libc::socklen_t;
        let r = if peer {
            libc::getpeername(fd as i32, a, l)
        } else {
            libc::getsockname(fd as i32, a, l)
        };
        ret(r as i64)
    }
    #[cfg(not(target_os = "linux"))]
    // SAFETY: the caller guarantees the out pointers.
    unsafe {
        imp::getname(fd, addr, addrlen, peer)
    }
}

/// `sendto(fd, buf, len, flags, addr, addrlen)`.
///
/// # Safety
/// `buf` must span `len` readable bytes; `addr`, if non-null, a `sockaddr`.
pub unsafe fn sendto(fd: u64, buf: u64, len: u64, flags: u64, addr: u64, addrlen: u64) -> i64 {
    #[cfg(target_os = "linux")]
    // SAFETY: the host validates the buffer and sockaddr.
    unsafe {
        ret(libc::sendto(
            fd as i32,
            buf as *const libc::c_void,
            len as usize,
            flags as i32,
            addr as *const libc::sockaddr,
            addrlen as libc::socklen_t,
        ) as i64)
    }
    #[cfg(not(target_os = "linux"))]
    // SAFETY: the caller guarantees the buffer and sockaddr.
    unsafe {
        imp::sendto(fd, buf, len, flags, addr, addrlen)
    }
}

/// `recvfrom(fd, buf, len, flags, addr, addrlen)`.
///
/// # Safety
/// `buf` must span `len` writable bytes; `addr`/`addrlen`, if non-null, a
/// writable `sockaddr` and its length.
pub unsafe fn recvfrom(fd: u64, buf: u64, len: u64, flags: u64, addr: u64, addrlen: u64) -> i64 {
    #[cfg(target_os = "linux")]
    // SAFETY: the host validates the buffer and out pointers.
    unsafe {
        ret(libc::recvfrom(
            fd as i32,
            buf as *mut libc::c_void,
            len as usize,
            flags as i32,
            addr as *mut libc::sockaddr,
            addrlen as *mut libc::socklen_t,
        ) as i64)
    }
    #[cfg(not(target_os = "linux"))]
    // SAFETY: the caller guarantees the buffer and out pointers.
    unsafe {
        imp::recvfrom(fd, buf, len, flags, addr, addrlen)
    }
}

/// `setsockopt(fd, level, optname, optval, optlen)`.
///
/// # Safety
/// `optval` must span `optlen` readable bytes.
pub unsafe fn setsockopt(fd: u64, level: u64, optname: u64, optval: u64, optlen: u64) -> i64 {
    #[cfg(target_os = "linux")]
    // SAFETY: the host validates the option buffer.
    unsafe {
        ret(libc::setsockopt(
            fd as i32,
            level as i32,
            optname as i32,
            optval as *const libc::c_void,
            optlen as libc::socklen_t,
        ) as i64)
    }
    #[cfg(not(target_os = "linux"))]
    // SAFETY: the caller guarantees the option buffer.
    unsafe {
        imp::setsockopt(fd, level, optname, optval, optlen)
    }
}

/// `getsockopt(fd, level, optname, optval, optlen)`.
///
/// # Safety
/// `optval`/`optlen` must be writable for the option and its length.
pub unsafe fn getsockopt(fd: u64, level: u64, optname: u64, optval: u64, optlen: u64) -> i64 {
    #[cfg(target_os = "linux")]
    // SAFETY: the host validates the out pointers.
    unsafe {
        ret(libc::getsockopt(
            fd as i32,
            level as i32,
            optname as i32,
            optval as *mut libc::c_void,
            optlen as *mut libc::socklen_t,
        ) as i64)
    }
    #[cfg(not(target_os = "linux"))]
    // SAFETY: the caller guarantees the out pointers.
    unsafe {
        imp::getsockopt(fd, level, optname, optval, optlen)
    }
}

/// `shutdown(fd, how)`. `how` (`SHUT_RD`/`WR`/`RDWR`) matches on both.
///
/// # Safety
/// No pointer arguments.
pub unsafe fn shutdown(fd: u64, how: u64) -> i64 {
    // SAFETY: plain host call on both platforms.
    unsafe { ret(libc::shutdown(fd as i32, how as i32) as i64) }
}

/// `sendmsg(fd, msg, flags)` (scatter send; ancillary data not supported).
///
/// # Safety
/// `msg` must point to a valid `msghdr` with valid `iov`/`name`.
pub unsafe fn sendmsg(fd: u64, msg: u64, flags: u64) -> i64 {
    #[cfg(target_os = "linux")]
    // SAFETY: the host validates the msghdr.
    unsafe {
        ret(libc::sendmsg(fd as i32, msg as *const libc::msghdr, flags as i32) as i64)
    }
    #[cfg(not(target_os = "linux"))]
    // SAFETY: the caller guarantees the msghdr.
    unsafe {
        imp::sendmsg(fd, msg, flags)
    }
}

/// `recvmsg(fd, msg, flags)` (scatter receive; ancillary data not supported).
///
/// # Safety
/// `msg` must point to a valid `msghdr` with writable `iov`/`name`.
pub unsafe fn recvmsg(fd: u64, msg: u64, flags: u64) -> i64 {
    #[cfg(target_os = "linux")]
    // SAFETY: the host validates the msghdr.
    unsafe {
        ret(libc::recvmsg(fd as i32, msg as *mut libc::msghdr, flags as i32) as i64)
    }
    #[cfg(not(target_os = "linux"))]
    // SAFETY: the caller guarantees the msghdr.
    unsafe {
        imp::recvmsg(fd, msg, flags)
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use crate::host::{last_error, ret};
    use fwe_abi::socket::*;
    use fwe_abi::{err, errno};

    /// Translate a Linux address family to the host value.
    fn host_domain(domain: u64) -> Result<i32, i64> {
        Ok(match domain {
            AF_UNIX => libc::AF_UNIX,
            AF_INET => libc::AF_INET,
            AF_INET6 => libc::AF_INET6,
            _ => return Err(err(errno::EAFNOSUPPORT)),
        })
    }

    fn apply_flags(fd: i32, type_or_flags: u64) {
        // SAFETY: plain host calls on a socket we just created.
        unsafe {
            if type_or_flags & SOCK_NONBLOCK != 0 {
                let fl = libc::fcntl(fd, libc::F_GETFL);
                libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
            }
            if type_or_flags & SOCK_CLOEXEC != 0 {
                libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
            }
            // Broken-pipe writes should return EPIPE, not raise a signal.
            let on: i32 = 1;
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                &on as *const _ as *const libc::c_void,
                4,
            );
        }
    }

    pub unsafe fn socket(domain: u64, type_: u64, protocol: u64) -> i64 {
        let dom = match host_domain(domain) {
            Ok(d) => d,
            Err(e) => return e,
        };
        let base = (type_ & !(SOCK_NONBLOCK | SOCK_CLOEXEC)) as i32;
        // SAFETY: plain host call.
        let fd = unsafe { libc::socket(dom, base, protocol as i32) };
        if fd < 0 {
            return last_error();
        }
        apply_flags(fd, type_);
        fd as i64
    }

    pub unsafe fn socketpair(domain: u64, type_: u64, protocol: u64, sv: u64) -> i64 {
        let dom = match host_domain(domain) {
            Ok(d) => d,
            Err(e) => return e,
        };
        let base = (type_ & !(SOCK_NONBLOCK | SOCK_CLOEXEC)) as i32;
        let mut fds = [0i32; 2];
        // SAFETY: plain host call with a 2-element array.
        let r = unsafe { libc::socketpair(dom, base, protocol as i32, fds.as_mut_ptr()) };
        if r < 0 {
            return last_error();
        }
        apply_flags(fds[0], type_);
        apply_flags(fds[1], type_);
        // SAFETY: the caller guarantees two writable i32s.
        unsafe {
            (sv as *mut i32).write_unaligned(fds[0]);
            ((sv + 4) as *mut i32).write_unaligned(fds[1]);
        }
        0
    }

    /// Convert a guest (Linux) `sockaddr` at `addr`/`len` into host layout in
    /// `out`, returning the host length.
    ///
    /// # Safety
    /// `addr` must span `len` readable bytes.
    unsafe fn to_host(addr: u64, len: u64, out: &mut [u8; 128]) -> Result<libc::socklen_t, i64> {
        // SAFETY: the caller guarantees at least two readable bytes.
        let fam = unsafe { (addr as *const u16).read_unaligned() } as u64;
        let (total, host_fam) = match fam {
            AF_INET => (16usize, libc::AF_INET as u8),
            AF_INET6 => (28usize, libc::AF_INET6 as u8),
            AF_UNIX => return Err(err(errno::EAFNOSUPPORT)),
            _ => return Err(err(errno::EAFNOSUPPORT)),
        };
        if (len as usize) < total {
            return Err(err(errno::EINVAL));
        }
        out[0] = total as u8;
        out[1] = host_fam;
        // SAFETY: the port/address bytes after the family are identical in
        // layout and fit within `out`.
        unsafe {
            std::ptr::copy_nonoverlapping(
                (addr + 2) as *const u8,
                out.as_mut_ptr().add(2),
                total - 2,
            );
        }
        Ok(total as libc::socklen_t)
    }

    /// Write a host `sockaddr` back to a guest buffer in Linux layout, honoring
    /// the guest capacity `dst_cap`; returns the full Linux length.
    ///
    /// # Safety
    /// `dst`, if non-zero, must be writable for `dst_cap` bytes.
    unsafe fn to_guest(host: &[u8; 128], host_len: libc::socklen_t, dst: u64, dst_cap: u32) -> u32 {
        let total = host_len as usize;
        let lfam: u16 = match host.get(1).copied().map(|b| b as i32) {
            Some(f) if f == libc::AF_INET => AF_INET as u16,
            Some(f) if f == libc::AF_INET6 => AF_INET6 as u16,
            Some(f) if f == libc::AF_UNIX => AF_UNIX as u16,
            _ => 0,
        };
        let mut lb = [0u8; 128];
        lb[0..2].copy_from_slice(&lfam.to_ne_bytes());
        if total > 2 {
            lb[2..total].copy_from_slice(&host[2..total]);
        }
        if dst != 0 {
            let n = (total).min(dst_cap as usize);
            // SAFETY: the caller guarantees `dst_cap` writable bytes.
            unsafe { std::ptr::copy_nonoverlapping(lb.as_ptr(), dst as *mut u8, n) };
        }
        total as u32
    }

    pub unsafe fn bind(fd: u64, addr: u64, addrlen: u64) -> i64 {
        let mut hb = [0u8; 128];
        // SAFETY: the caller guarantees the sockaddr spans addrlen.
        let hlen = match unsafe { to_host(addr, addrlen, &mut hb) } {
            Ok(l) => l,
            Err(e) => return e,
        };
        // SAFETY: `hb` holds a valid host sockaddr of `hlen` bytes.
        ret(unsafe { libc::bind(fd as i32, hb.as_ptr() as *const libc::sockaddr, hlen) } as i64)
    }

    pub unsafe fn connect(fd: u64, addr: u64, addrlen: u64) -> i64 {
        let mut hb = [0u8; 128];
        // SAFETY: the caller guarantees the sockaddr spans addrlen.
        let hlen = match unsafe { to_host(addr, addrlen, &mut hb) } {
            Ok(l) => l,
            Err(e) => return e,
        };
        // SAFETY: `hb` holds a valid host sockaddr of `hlen` bytes.
        ret(unsafe { libc::connect(fd as i32, hb.as_ptr() as *const libc::sockaddr, hlen) } as i64)
    }

    pub unsafe fn accept4(fd: u64, addr: u64, addrlen: u64, flags: u64) -> i64 {
        let mut hb = [0u8; 128];
        let mut hl: libc::socklen_t = 128;
        let r = if addr != 0 {
            // SAFETY: `hb`/`hl` are valid out parameters.
            unsafe { libc::accept(fd as i32, hb.as_mut_ptr() as *mut libc::sockaddr, &mut hl) }
        } else {
            // SAFETY: null out parameters are permitted.
            unsafe { libc::accept(fd as i32, std::ptr::null_mut(), std::ptr::null_mut()) }
        };
        if r < 0 {
            return last_error();
        }
        if addr != 0 {
            // SAFETY: the caller guarantees a writable length word.
            let cap = unsafe { (addrlen as *const u32).read_unaligned() };
            // SAFETY: `hb` holds `hl` host bytes; `addr`/`addrlen` are writable.
            let full = unsafe { to_guest(&hb, hl, addr, cap) };
            // SAFETY: writable length word.
            unsafe { (addrlen as *mut u32).write_unaligned(full) };
        }
        apply_flags(r, flags);
        r as i64
    }

    pub unsafe fn getname(fd: u64, addr: u64, addrlen: u64, peer: bool) -> i64 {
        let mut hb = [0u8; 128];
        let mut hl: libc::socklen_t = 128;
        let a = hb.as_mut_ptr() as *mut libc::sockaddr;
        // SAFETY: valid out parameters.
        let r = unsafe {
            if peer {
                libc::getpeername(fd as i32, a, &mut hl)
            } else {
                libc::getsockname(fd as i32, a, &mut hl)
            }
        };
        if r < 0 {
            return last_error();
        }
        // SAFETY: the caller guarantees a writable length word.
        let cap = unsafe { (addrlen as *const u32).read_unaligned() };
        // SAFETY: `hb` holds `hl` host bytes; `addr`/`addrlen` are writable.
        let full = unsafe { to_guest(&hb, hl, addr, cap) };
        // SAFETY: writable length word.
        unsafe { (addrlen as *mut u32).write_unaligned(full) };
        0
    }

    /// Translate Linux `send`/`recv` flags to host flags.
    fn msg_flags_to_host(flags: u64) -> i32 {
        let mut h = 0;
        if flags & MSG_OOB != 0 {
            h |= libc::MSG_OOB;
        }
        if flags & MSG_PEEK != 0 {
            h |= libc::MSG_PEEK;
        }
        if flags & MSG_DONTROUTE != 0 {
            h |= libc::MSG_DONTROUTE;
        }
        if flags & MSG_TRUNC != 0 {
            h |= libc::MSG_TRUNC;
        }
        if flags & MSG_DONTWAIT != 0 {
            h |= libc::MSG_DONTWAIT;
        }
        if flags & MSG_EOR != 0 {
            h |= libc::MSG_EOR;
        }
        if flags & MSG_WAITALL != 0 {
            h |= libc::MSG_WAITALL;
        }
        // MSG_NOSIGNAL: emulated by SO_NOSIGPIPE on the socket.
        h
    }

    fn msg_flags_from_host(flags: i32) -> i32 {
        let mut l = 0u64;
        if flags & libc::MSG_OOB != 0 {
            l |= MSG_OOB;
        }
        if flags & libc::MSG_TRUNC != 0 {
            l |= MSG_TRUNC;
        }
        if flags & libc::MSG_CTRUNC != 0 {
            l |= MSG_CTRUNC;
        }
        if flags & libc::MSG_EOR != 0 {
            l |= MSG_EOR;
        }
        l as i32
    }

    pub unsafe fn sendto(fd: u64, buf: u64, len: u64, flags: u64, addr: u64, addrlen: u64) -> i64 {
        let hflags = msg_flags_to_host(flags);
        if addr != 0 && addrlen != 0 {
            let mut hb = [0u8; 128];
            // SAFETY: the caller guarantees the sockaddr spans addrlen.
            let hlen = match unsafe { to_host(addr, addrlen, &mut hb) } {
                Ok(l) => l,
                Err(e) => return e,
            };
            // SAFETY: valid buffer and host sockaddr.
            ret(unsafe {
                libc::sendto(
                    fd as i32,
                    buf as *const libc::c_void,
                    len as usize,
                    hflags,
                    hb.as_ptr() as *const libc::sockaddr,
                    hlen,
                )
            } as i64)
        } else {
            // SAFETY: valid buffer; no destination address.
            ret(unsafe {
                libc::sendto(
                    fd as i32,
                    buf as *const libc::c_void,
                    len as usize,
                    hflags,
                    std::ptr::null(),
                    0,
                )
            } as i64)
        }
    }

    pub unsafe fn recvfrom(
        fd: u64,
        buf: u64,
        len: u64,
        flags: u64,
        addr: u64,
        addrlen: u64,
    ) -> i64 {
        let hflags = msg_flags_to_host(flags);
        if addr != 0 {
            let mut hb = [0u8; 128];
            let mut hl: libc::socklen_t = 128;
            // SAFETY: valid buffer and out sockaddr.
            let r = unsafe {
                libc::recvfrom(
                    fd as i32,
                    buf as *mut libc::c_void,
                    len as usize,
                    hflags,
                    hb.as_mut_ptr() as *mut libc::sockaddr,
                    &mut hl,
                )
            };
            if r < 0 {
                return last_error();
            }
            if addrlen != 0 {
                // SAFETY: writable length word.
                let cap = unsafe { (addrlen as *const u32).read_unaligned() };
                // SAFETY: `hb` holds `hl` bytes; `addr`/`addrlen` writable.
                let full = unsafe { to_guest(&hb, hl, addr, cap) };
                // SAFETY: writable length word.
                unsafe { (addrlen as *mut u32).write_unaligned(full) };
            }
            r as i64
        } else {
            // SAFETY: valid buffer; no source address wanted.
            ret(unsafe {
                libc::recvfrom(
                    fd as i32,
                    buf as *mut libc::c_void,
                    len as usize,
                    hflags,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            } as i64)
        }
    }

    /// Map a Linux `(level, optname)` to the host pair.
    fn opt_to_host(level: u64, optname: u64) -> Result<(i32, i32), i64> {
        if level == SOL_SOCKET {
            let o = match optname {
                SO_REUSEADDR => libc::SO_REUSEADDR,
                SO_TYPE => libc::SO_TYPE,
                SO_ERROR => libc::SO_ERROR,
                SO_DONTROUTE => libc::SO_DONTROUTE,
                SO_BROADCAST => libc::SO_BROADCAST,
                SO_SNDBUF => libc::SO_SNDBUF,
                SO_RCVBUF => libc::SO_RCVBUF,
                SO_KEEPALIVE => libc::SO_KEEPALIVE,
                SO_OOBINLINE => libc::SO_OOBINLINE,
                SO_LINGER => libc::SO_LINGER,
                SO_REUSEPORT => libc::SO_REUSEPORT,
                SO_RCVTIMEO => libc::SO_RCVTIMEO,
                SO_SNDTIMEO => libc::SO_SNDTIMEO,
                SO_ACCEPTCONN => libc::SO_ACCEPTCONN,
                _ => return Err(err(errno::ENOPROTOOPT)),
            };
            return Ok((libc::SOL_SOCKET, o));
        }
        // IPPROTO_TCP: TCP_NODELAY differs (1 on Linux, 4 on macOS); other
        // protocol levels and options share values closely enough to pass
        // through.
        if level == libc::IPPROTO_TCP as u64 {
            let o = if optname == 1 { libc::TCP_NODELAY } else { optname as i32 };
            return Ok((libc::IPPROTO_TCP, o));
        }
        Ok((level as i32, optname as i32))
    }

    pub unsafe fn setsockopt(fd: u64, level: u64, optname: u64, optval: u64, optlen: u64) -> i64 {
        let (hl, ho) = match opt_to_host(level, optname) {
            Ok(v) => v,
            Err(e) => return e,
        };
        // SAFETY: the caller guarantees the option buffer spans optlen.
        ret(unsafe {
            libc::setsockopt(
                fd as i32,
                hl,
                ho,
                optval as *const libc::c_void,
                optlen as libc::socklen_t,
            )
        } as i64)
    }

    pub unsafe fn getsockopt(fd: u64, level: u64, optname: u64, optval: u64, optlen: u64) -> i64 {
        let (hl, ho) = match opt_to_host(level, optname) {
            Ok(v) => v,
            Err(e) => return e,
        };
        // SAFETY: the caller guarantees writable option and length buffers.
        ret(unsafe {
            libc::getsockopt(
                fd as i32,
                hl,
                ho,
                optval as *mut libc::c_void,
                optlen as *mut libc::socklen_t,
            )
        } as i64)
    }

    /// Read the fields of a guest (Linux) `msghdr`.
    unsafe fn read_msghdr(msg: u64) -> (u64, u32, u64, u64, u64, u64) {
        // SAFETY: the caller guarantees a valid msghdr.
        unsafe {
            (
                (msg as *const u64).read_unaligned(),        // msg_name
                ((msg + 8) as *const u32).read_unaligned(),  // msg_namelen
                ((msg + 16) as *const u64).read_unaligned(), // msg_iov
                ((msg + 24) as *const u64).read_unaligned(), // msg_iovlen
                ((msg + 32) as *const u64).read_unaligned(), // msg_control
                ((msg + 40) as *const u64).read_unaligned(), // msg_controllen
            )
        }
    }

    pub unsafe fn sendmsg(fd: u64, msg: u64, flags: u64) -> i64 {
        // SAFETY: the caller guarantees a valid msghdr.
        let (name, namelen, iov, iovlen, _control, controllen) = unsafe { read_msghdr(msg) };
        if controllen != 0 {
            // Ancillary data (e.g. SCM_RIGHTS fd passing) is not translated yet.
            return err(errno::ENOSYS);
        }
        let mut hb = [0u8; 128];
        let (name_ptr, name_len) = if name != 0 && namelen != 0 {
            // SAFETY: the caller guarantees the name spans namelen.
            match unsafe { to_host(name, namelen as u64, &mut hb) } {
                Ok(l) => (hb.as_mut_ptr() as *mut libc::c_void, l),
                Err(e) => return e,
            }
        } else {
            (std::ptr::null_mut(), 0)
        };
        let hmsg = libc::msghdr {
            msg_name: name_ptr,
            msg_namelen: name_len,
            msg_iov: iov as *mut libc::iovec,
            msg_iovlen: iovlen as libc::c_int,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        // SAFETY: `hmsg` references the guest's iov and a local name buffer.
        ret(unsafe { libc::sendmsg(fd as i32, &hmsg, msg_flags_to_host(flags)) } as i64)
    }

    pub unsafe fn recvmsg(fd: u64, msg: u64, flags: u64) -> i64 {
        // SAFETY: the caller guarantees a valid msghdr.
        let (name, namelen, iov, iovlen, _control, _controllen) = unsafe { read_msghdr(msg) };
        let want_name = name != 0 && namelen != 0;
        let mut hb = [0u8; 128];
        let mut hmsg = libc::msghdr {
            msg_name: if want_name {
                hb.as_mut_ptr() as *mut libc::c_void
            } else {
                std::ptr::null_mut()
            },
            msg_namelen: if want_name { namelen.min(128) } else { 0 },
            msg_iov: iov as *mut libc::iovec,
            msg_iovlen: iovlen as libc::c_int,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };
        // SAFETY: `hmsg` references the guest's iov and a local name buffer.
        let r = unsafe { libc::recvmsg(fd as i32, &mut hmsg, msg_flags_to_host(flags)) };
        if r < 0 {
            return last_error();
        }
        if want_name {
            // SAFETY: `hb` holds `hmsg.msg_namelen` bytes; `name` is writable.
            let full = unsafe { to_guest(&hb, hmsg.msg_namelen, name, namelen) };
            // SAFETY: the msg_namelen field is writable.
            unsafe { ((msg + 8) as *mut u32).write_unaligned(full) };
        }
        // No ancillary data produced; report none and translate out-flags.
        // SAFETY: the controllen and flags fields are writable.
        unsafe {
            ((msg + 40) as *mut u64).write_unaligned(0);
            ((msg + 48) as *mut i32).write_unaligned(msg_flags_from_host(hmsg.msg_flags));
        }
        r as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fwe_abi::socket::*;

    fn close(fd: i64) {
        // SAFETY: plain host close of a socket we opened.
        unsafe { libc::close(fd as i32) };
    }

    /// Build a Linux `sockaddr_in` for 127.0.0.1:`port` (network byte order).
    fn sockaddr_in_v4(port: u16) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
        b[2..4].copy_from_slice(&port.to_be_bytes());
        b[4..8].copy_from_slice(&[127, 0, 0, 1]);
        b
    }

    #[test]
    fn socketpair_round_trip() {
        let mut sv = [0i32; 2];
        let p = sv.as_mut_ptr() as u64;
        // SAFETY: `sv` holds two i32s.
        let r = unsafe { socketpair(AF_UNIX, SOCK_STREAM, 0, p) };
        assert_eq!(r, 0, "socketpair failed: {r}");
        let msg = b"ping";
        // SAFETY: valid fd and buffer.
        let n = unsafe { libc::write(sv[0], msg.as_ptr() as *const _, msg.len()) };
        assert_eq!(n, 4);
        let mut buf = [0u8; 8];
        // SAFETY: valid fd and buffer.
        let got = unsafe { libc::read(sv[1], buf.as_mut_ptr() as *mut _, buf.len()) };
        assert_eq!(got, 4);
        assert_eq!(&buf[..4], b"ping");
        close(sv[0] as i64);
        close(sv[1] as i64);
    }

    #[test]
    fn udp_v4_loopback() {
        // SAFETY: no pointers.
        let rx = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
        assert!(rx >= 0, "socket rx: {rx}");
        // SAFETY: no pointers.
        let tx = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
        assert!(tx >= 0, "socket tx: {tx}");

        let addr = sockaddr_in_v4(0);
        // SAFETY: valid sockaddr.
        assert_eq!(unsafe { bind(rx as u64, addr.as_ptr() as u64, 16) }, 0);

        // Learn the bound port via getsockname.
        let mut got = [0u8; 16];
        let mut len: u32 = 16;
        // SAFETY: writable out sockaddr and length.
        let r = unsafe {
            getname(rx as u64, got.as_mut_ptr() as u64, &mut len as *mut _ as u64, false)
        };
        assert_eq!(r, 0);
        let port = u16::from_be_bytes([got[2], got[3]]);
        assert_ne!(port, 0, "kernel should have assigned a port");

        // Send a datagram to 127.0.0.1:port and receive it.
        let dst = sockaddr_in_v4(port);
        let payload = b"hello-udp";
        // SAFETY: valid buffer and sockaddr.
        let sent = unsafe {
            sendto(
                tx as u64,
                payload.as_ptr() as u64,
                payload.len() as u64,
                0,
                dst.as_ptr() as u64,
                16,
            )
        };
        assert_eq!(sent, payload.len() as i64, "sendto: {sent}");

        let mut buf = [0u8; 32];
        // SAFETY: valid buffer; no source wanted.
        let recvd = unsafe { recvfrom(rx as u64, buf.as_mut_ptr() as u64, 32, 0, 0, 0) };
        assert_eq!(recvd, payload.len() as i64, "recvfrom: {recvd}");
        assert_eq!(&buf[..payload.len()], payload);

        close(rx);
        close(tx);
    }

    /// Build a Linux `sockaddr_in6` for the wildcard address `[::]`:`port`
    /// (28 bytes). The wildcard binds wherever IPv6 is available at all,
    /// without depending on loopback routing.
    fn sockaddr_in6_any(port: u16) -> [u8; 28] {
        let mut b = [0u8; 28];
        b[0..2].copy_from_slice(&(AF_INET6 as u16).to_ne_bytes());
        b[2..4].copy_from_slice(&port.to_be_bytes());
        b
    }

    /// Validates the `sockaddr_in6` translation (family 10↔30, 28-byte layout)
    /// by binding to `[::]:0` and reading the result back with getsockname.
    /// Skips where IPv6 is unavailable (some sandboxes), which CI runners are
    /// not.
    #[test]
    fn v6_sockaddr_round_trip() {
        // SAFETY: no pointers.
        let fd = unsafe { socket(AF_INET6, SOCK_DGRAM, 0) };
        if fd < 0 {
            eprintln!("skipping: AF_INET6 unavailable ({fd})");
            return;
        }
        let addr = sockaddr_in6_any(0);
        // SAFETY: valid sockaddr_in6.
        let b = unsafe { bind(fd as u64, addr.as_ptr() as u64, 28) };
        if b != 0 {
            eprintln!("skipping: IPv6 bind unavailable ({b})");
            close(fd);
            return;
        }

        let mut got = [0u8; 28];
        let mut len: u32 = 28;
        // SAFETY: writable out sockaddr and length.
        let r = unsafe {
            getname(fd as u64, got.as_mut_ptr() as u64, &mut len as *mut _ as u64, false)
        };
        assert_eq!(r, 0);
        // Family must come back as the Linux AF_INET6 value, not the host's.
        assert_eq!(u16::from_ne_bytes([got[0], got[1]]) as u64, AF_INET6);
        assert_eq!(len, 28, "getsockname should report the full sockaddr_in6 length");
        assert_ne!(u16::from_be_bytes([got[2], got[3]]), 0, "a port should be assigned");
        close(fd);
    }

    #[test]
    fn tcp_v4_loopback() {
        // SAFETY: no pointers.
        let srv = unsafe { socket(AF_INET, SOCK_STREAM, 0) };
        assert!(srv >= 0);
        let one: i32 = 1;
        // SAFETY: valid option buffer.
        unsafe {
            setsockopt(srv as u64, SOL_SOCKET, SO_REUSEADDR, &one as *const _ as u64, 4);
        }
        let addr = sockaddr_in_v4(0);
        // SAFETY: valid sockaddr.
        assert_eq!(unsafe { bind(srv as u64, addr.as_ptr() as u64, 16) }, 0);
        // SAFETY: no pointers.
        assert_eq!(unsafe { listen(srv as u64, 1) }, 0);

        let mut sa = [0u8; 16];
        let mut salen: u32 = 16;
        // SAFETY: writable out sockaddr and length.
        let r = unsafe {
            getname(srv as u64, sa.as_mut_ptr() as u64, &mut salen as *mut _ as u64, false)
        };
        assert_eq!(r, 0);
        let port = u16::from_be_bytes([sa[2], sa[3]]);

        // Connect from a client socket, accept on the server, exchange bytes.
        // SAFETY: no pointers.
        let cli = unsafe { socket(AF_INET, SOCK_STREAM, 0) };
        assert!(cli >= 0);
        let dst = sockaddr_in_v4(port);
        // A blocking connect to a listening loopback socket completes without a
        // concurrent accept because the backlog queues it.
        // SAFETY: valid sockaddr.
        assert_eq!(unsafe { connect(cli as u64, dst.as_ptr() as u64, 16) }, 0);

        // SAFETY: no out address wanted.
        let acc = unsafe { accept4(srv as u64, 0, 0, 0) };
        assert!(acc >= 0, "accept: {acc}");

        let msg = b"tcp-hi";
        // SAFETY: valid buffer.
        let sent = unsafe { sendto(cli as u64, msg.as_ptr() as u64, msg.len() as u64, 0, 0, 0) };
        assert_eq!(sent, msg.len() as i64);
        let mut buf = [0u8; 16];
        // SAFETY: valid buffer.
        let got = unsafe { recvfrom(acc as u64, buf.as_mut_ptr() as u64, 16, 0, 0, 0) };
        assert_eq!(got, msg.len() as i64);
        assert_eq!(&buf[..msg.len()], msg);

        close(acc);
        close(cli);
        close(srv);
    }

    #[test]
    fn getsockopt_reports_type() {
        // SAFETY: no pointers.
        let fd = unsafe { socket(AF_INET, SOCK_STREAM, 0) };
        assert!(fd >= 0);
        let mut ty: i32 = -1;
        let mut len: u32 = 4;
        // SAFETY: writable option and length buffers.
        let r = unsafe {
            getsockopt(
                fd as u64,
                SOL_SOCKET,
                SO_TYPE,
                &mut ty as *mut _ as u64,
                &mut len as *mut _ as u64,
            )
        };
        assert_eq!(r, 0, "getsockopt: {r}");
        assert_eq!(ty as u64, SOCK_STREAM);
        close(fd);
    }
}
