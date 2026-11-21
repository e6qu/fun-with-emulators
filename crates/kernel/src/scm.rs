//! Control messages on Unix sockets: the descriptors `SCM_RIGHTS` passes
//! and the credentials `SCM_CREDENTIALS` carries, between Linux's layout
//! and the host's.
//!
//! Linux's `cmsghdr` has a 64-bit length and 8-byte alignment, macOS's a
//! 32-bit one and 4-byte alignment, so each message is re-encoded. A send
//! takes every `SCM_RIGHTS` message of the guest's buffer, as Linux does,
//! up to its 253 descriptors (`SCM_MAX_FD`), into one host message. A
//! receive writes as many descriptors as the guest's buffer holds and
//! closes the rest (`MSG_CTRUNC`), as Linux does: the host installs them
//! all whatever the buffer.
//!
//! A descriptor fwe stands in for (an eventfd, a timerfd, a signalfd, a
//! netlink socket, a process descriptor, a memfd opened again read-only)
//! is more than its host object, so
//! the sender adds a *bundle*: a host datagram socket, sent as the last
//! descriptor, holding a manifest of what each such descriptor is and the
//! host objects behind it (an eventfd's pipe end and counter file, a
//! netlink socket's other end). The host passes no kqueue, so a timerfd or
//! process descriptor goes as a placeholder (the bundle again) and the
//! receiver makes its own: a timerfd with the same schedule, a process
//! descriptor of the same process; a socket made in a network namespace of
//! fwe's stays in it; a signalfd is made anew in the
//! receiver with the same mask, reading the receiver's signals as Linux's
//! does. The receiver recognises the bundle by its buffer size and the
//! manifest's magic number, takes what it describes, and closes it, so the
//! guest never sees it. The manifest also carries credentials the sender
//! gave with `SCM_CREDENTIALS`.

use crate::snapshot::{Dec, Enc};
use fwe_abi::errno;
use fwe_abi::socket::{CMSG_HDR, SCM_MAX_FD, SCM_RIGHTS, SOL_SOCKET};

/// `SCM_CREDENTIALS`, and the size of its `struct ucred`.
pub const SCM_CREDENTIALS: i32 = 2;
const UCRED: usize = 12;

/// A bundle's send buffer size: what marks one (an odd size no socket of
/// fwe's or a program's is given).
const BUNDLE_MARK: libc::c_int = 196_613;
/// The manifest's first word.
const MAGIC: u64 = 0x6677_655f_7363_6d31;
/// Descriptors per datagram of companions in the bundle.
const CHUNK: usize = 200;

/// The kinds of descriptor a bundle describes.
pub(crate) mod kind {
    pub const EVENTFD: u8 = 1;
    pub const TIMERFD: u8 = 2;
    pub const SIGNALFD: u8 = 3;
    pub const NETLINK: u8 = 4;
    pub const PIDFD: u8 = 5;
    pub const NETNS: u8 = 6;
    /// A memfd opened again read-only ([`crate::fdmarks::Mark::ReadOnly`]).
    pub const READ_ONLY: u8 = 7;
}

/// What a descriptor fwe stands in for takes to another process: its kind,
/// its state, the host descriptors behind it (borrowed: the sender keeps
/// its own), and whether its own host object cannot be passed (a kqueue),
/// so that a placeholder goes in its place.
pub(crate) struct Export {
    pub kind: u8,
    pub state: Vec<u8>,
    pub companions: Vec<i32>,
    pub placeholder: bool,
}

/// Credentials as they travel: the sender's host pid and its user and
/// group ids in the initial user namespace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Creds {
    pub host_pid: i32,
    pub uid: u32,
    pub gid: u32,
}

/// What a guest's control messages ask to send.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outgoing {
    pub fds: Vec<i32>,
    /// `SCM_CREDENTIALS` as the guest wrote it: pid, uid, gid.
    pub creds: Option<[u32; 3]>,
}

/// Read a guest control buffer as Linux's `__scm_send` does: each
/// message's length must fit (`EINVAL`); messages of other levels are
/// passed over; at `SOL_SOCKET`, `SCM_RIGHTS` adds descriptors (each open,
/// `EBADF`; at most [`SCM_MAX_FD`] in all, `EINVAL`), `SCM_CREDENTIALS`
/// must be a whole `ucred`, and any other type is `EINVAL`.
pub fn parse(ctl: &[u8]) -> Result<Outgoing, i32> {
    let mut out = Outgoing::default();
    let word32 = |o: usize| i32::from_ne_bytes(ctl[o..o + 4].try_into().unwrap());
    let mut at = 0usize;
    while at + CMSG_HDR <= ctl.len() {
        let len = u64::from_ne_bytes(ctl[at..at + 8].try_into().unwrap());
        if len < CMSG_HDR as u64 || len > (ctl.len() - at) as u64 {
            return Err(errno::EINVAL);
        }
        let len = len as usize;
        let (level, ty) = (word32(at + 8), word32(at + 12));
        if level == SOL_SOCKET as i32 {
            match ty {
                SCM_RIGHTS => {
                    let n = (len - CMSG_HDR) / 4;
                    if out.fds.len() + n > SCM_MAX_FD {
                        return Err(errno::EINVAL);
                    }
                    for i in 0..n {
                        let fd = word32(at + CMSG_HDR + 4 * i);
                        // SAFETY: F_GETFD only queries the descriptor.
                        let open = unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0;
                        if fd < 0 || !crate::fdtable::guest_visible(fd) || !open {
                            return Err(errno::EBADF);
                        }
                        out.fds.push(fd);
                    }
                }
                SCM_CREDENTIALS => {
                    if len != CMSG_HDR + UCRED {
                        return Err(errno::EINVAL);
                    }
                    let w = |i: usize| word32(at + CMSG_HDR + 4 * i) as u32;
                    out.creds = Some([w(0), w(1), w(2)]);
                }
                _ => return Err(errno::EINVAL),
            }
        }
        at += (len + 7) & !7;
    }
    Ok(out)
}

/// A message's host control data, ready to send: the `SCM_RIGHTS` message
/// and the bundle that goes with it. Once dropped, the bundle's end that
/// was sent is kept until the receiver has taken what it holds
/// ([`PENDING`]); the other is closed.
pub struct Prepared {
    pub buf: Vec<u8>,
    bundle: Option<[i32; 2]>,
}

impl Prepared {
    /// The message did not go: its bundle is closed at once.
    pub fn unsent(mut self) {
        for fd in self.bundle.take().into_iter().flatten() {
            // SAFETY: the bundle's ends, made by `prepare`.
            unsafe { libc::close(fd) };
        }
    }
}

impl Drop for Prepared {
    fn drop(&mut self) {
        let Some([w, r]) = self.bundle else { return };
        // SAFETY: the end written to, made by `prepare`.
        unsafe { libc::close(w) };
        let mut p = PENDING.lock().unwrap_or_else(|e| e.into_inner());
        p.push(r);
        sweep(&mut p);
    }
}

/// The bundles sent and not yet emptied by their receivers. The host
/// collects descriptors in flight that no process holds, and a collection
/// that runs while a message is on its way can take a bundle held only
/// in flight for unreachable and empty it, so the sender holds each until
/// its receiver has read it (or the sender ends).
pub(crate) static PENDING: std::sync::Mutex<Vec<i32>> = std::sync::Mutex::new(Vec::new());

/// Close the pending bundles their receivers have emptied.
fn sweep(p: &mut Vec<i32>) {
    p.retain(|&b| {
        let mut n: libc::c_int = 0;
        let mut l = 4 as libc::socklen_t;
        // SAFETY: valid out-parameters on fwe's own descriptor.
        let r = unsafe {
            libc::getsockopt(
                b,
                libc::SOL_SOCKET,
                libc::SO_NREAD,
                (&mut n as *mut i32).cast(),
                &mut l,
            )
        };
        let keep = r == 0 && n > 0;
        if !keep {
            // SAFETY: as above, no longer needed.
            unsafe { libc::close(b) };
        }
        keep
    });
}

/// Make the host control data for `fds` and the credentials `creds`
/// (already checked): `fds` with each descriptor fwe stands in for
/// described in a bundle, and the credentials in its manifest.
pub fn prepare(fds: &[i32], creds: Option<Creds>) -> Result<Prepared, i32> {
    let exports: Vec<Option<Export>> = fds.iter().map(|&fd| export(fd)).collect();
    let mut host: Vec<i32> = fds.to_vec();
    let mut p = Prepared { buf: Vec::new(), bundle: None };
    if creds.is_some() || exports.iter().any(Option::is_some) {
        let ends = make_bundle()?;
        p.bundle = Some(ends);
        fill_bundle(ends[0], &exports, creds)?;
        for (slot, x) in host.iter_mut().zip(&exports) {
            if x.as_ref().is_some_and(|x| x.placeholder) {
                *slot = ends[1];
            }
        }
        host.push(ends[1]);
    }
    if !host.is_empty() {
        p.buf = host_rights(&host);
    }
    Ok(p)
}

/// A host `SCM_RIGHTS` message (macOS layout: a 32-bit length, the level
/// and type, the descriptors 4-aligned) of `fds`.
fn host_rights(fds: &[i32]) -> Vec<u8> {
    let hdr = 12;
    let len = hdr + 4 * fds.len();
    let mut b = vec![0u8; len];
    b[0..4].copy_from_slice(&(len as u32).to_ne_bytes());
    b[4..8].copy_from_slice(&libc::SOL_SOCKET.to_ne_bytes());
    b[8..12].copy_from_slice(&libc::SCM_RIGHTS.to_ne_bytes());
    for (i, fd) in fds.iter().enumerate() {
        b[hdr + 4 * i..hdr + 4 * i + 4].copy_from_slice(&fd.to_ne_bytes());
    }
    b
}

/// The descriptors of the host control data `ctl` (every `SCM_RIGHTS`
/// message of it, macOS layout).
fn host_fds(ctl: &[u8]) -> Vec<i32> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + 12 <= ctl.len() {
        let w = |o: usize| u32::from_ne_bytes(ctl[o..o + 4].try_into().unwrap());
        let len = w(at) as usize;
        if len < 12 || at + len > ctl.len() {
            break;
        }
        if w(at + 4) as i32 == libc::SOL_SOCKET && w(at + 8) as i32 == libc::SCM_RIGHTS {
            out.extend((at + 12..at + len).step_by(4).map(|o| w(o) as i32));
        }
        at += (len + 3) & !3;
    }
    out
}

/// What a descriptor fwe stands in for takes along, if it is one.
fn export(fd: i32) -> Option<Export> {
    crate::specialfd::export(fd)
        .or_else(|| crate::signalfd::export(fd))
        .or_else(|| crate::netlink::export(fd))
        .or_else(|| crate::pidfd::export(fd))
        .or_else(|| crate::netns::export(fd))
        .or_else(|| crate::fdmarks::export(fd))
}

/// Take what a bundle describes for received descriptor `fd`: whether it
/// was taken (`fd` is then the stand-in, at the same number).
fn import(kind: u8, fd: i32, state: &[u8], companions: Vec<i32>) -> bool {
    let mut d = Dec::new(state);
    match kind {
        kind::EVENTFD | kind::TIMERFD => crate::specialfd::import(kind, fd, &mut d, companions),
        kind::SIGNALFD => crate::signalfd::import(fd, &mut d),
        kind::NETLINK => crate::netlink::import(fd, &mut d, companions),
        kind::PIDFD => crate::pidfd::import(fd, &mut d),
        kind::NETNS => crate::netns::import(fd, &mut d),
        kind::READ_ONLY => crate::fdmarks::import(fd),
        _ => false,
    }
}

/// Put `made` (a new host object) at descriptor number `slot`, in place of
/// what is there: whether it was.
pub(crate) fn replace(slot: i32, made: i32) -> bool {
    // SAFETY: plain host calls on descriptors this process holds.
    unsafe {
        let r = libc::dup2(made, slot);
        libc::close(made);
        r == slot
    }
}

fn last() -> i32 {
    crate::host::errno_to_linux(crate::host::last_errno())
}

/// A new bundle: a host datagram socket pair, its ends out of the guest's
/// reach. The first end is written to; the second is sent.
fn make_bundle() -> Result<[i32; 2], i32> {
    let mut sv = [0i32; 2];
    // SAFETY: a valid out-array of two descriptors.
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, sv.as_mut_ptr()) } != 0 {
        return Err(last());
    }
    let mut ends = [-1i32; 2];
    for (i, fd) in sv.into_iter().enumerate() {
        match crate::fdtable::reserve(fd) {
            Ok(r) => ends[i] = r,
            Err(e) => {
                for &f in ends.iter().chain(&sv[i + 1..]).filter(|&&f| f >= 0) {
                    // SAFETY: descriptors made above.
                    unsafe { libc::close(f) };
                }
                return Err(e);
            }
        }
    }
    let big: libc::c_int = 1 << 20;
    for (end, opt, v) in [
        (ends[0], libc::SO_SNDBUF, big),
        (ends[1], libc::SO_RCVBUF, big),
        (ends[1], libc::SO_SNDBUF, BUNDLE_MARK),
    ] {
        // SAFETY: a valid option value.
        unsafe { libc::setsockopt(end, libc::SOL_SOCKET, opt, (&v as *const i32).cast(), 4) };
    }
    Ok(ends)
}

/// Write the manifest of `exports` and `creds` to bundle end `w`, then the
/// descriptors behind them.
fn fill_bundle(w: i32, exports: &[Option<Export>], creds: Option<Creds>) -> Result<(), i32> {
    let mut e = Enc::new();
    e.u64(MAGIC);
    e.bool(creds.is_some());
    let c = creds.unwrap_or(Creds { host_pid: 0, uid: 0, gid: 0 });
    e.i32(c.host_pid);
    e.u32(c.uid);
    e.u32(c.gid);
    let described: Vec<(usize, &Export)> =
        exports.iter().enumerate().filter_map(|(i, x)| Some((i, x.as_ref()?))).collect();
    e.u64(described.len() as u64);
    let mut companions = Vec::new();
    for (i, x) in &described {
        e.u32(*i as u32);
        e.u8(x.kind);
        e.u32(x.companions.len() as u32);
        e.bytes(&x.state);
        companions.extend_from_slice(&x.companions);
    }
    let manifest = e.into_bytes();
    send_datagram(w, &manifest, &[])?;
    for chunk in companions.chunks(CHUNK) {
        send_datagram(w, &[0], chunk)?;
    }
    Ok(())
}

fn send_datagram(s: i32, data: &[u8], fds: &[i32]) -> Result<(), i32> {
    let mut iov = libc::iovec { iov_base: data.as_ptr() as *mut _, iov_len: data.len() };
    let mut ctl = if fds.is_empty() { Vec::new() } else { host_rights(fds) };
    // SAFETY: zeroed bytes are a valid `msghdr`, filled below.
    let mut m: libc::msghdr = unsafe { std::mem::zeroed() };
    m.msg_iov = &mut iov;
    m.msg_iovlen = 1;
    if !ctl.is_empty() {
        m.msg_control = ctl.as_mut_ptr().cast();
        m.msg_controllen = ctl.len() as _;
    }
    // SAFETY: a valid message of local buffers.
    if unsafe { libc::sendmsg(s, &m, 0) } < 0 { Err(last()) } else { Ok(()) }
}

/// Receive one datagram from bundle `b` (never waiting): its data and the
/// descriptors with it.
fn recv_datagram(b: i32, peek: bool) -> Option<(Vec<u8>, Vec<i32>)> {
    let mut size: libc::c_int = 0;
    let mut l = 4 as libc::socklen_t;
    // SAFETY: valid out-parameters.
    let r = unsafe {
        libc::getsockopt(
            b,
            libc::SOL_SOCKET,
            libc::SO_NREAD,
            (&mut size as *mut i32).cast(),
            &mut l,
        )
    };
    if r != 0 || size <= 0 {
        return None;
    }
    let mut data = vec![0u8; size as usize];
    let mut ctl = vec![0u8; 12 + 4 * CHUNK + 64];
    let mut iov = libc::iovec { iov_base: data.as_mut_ptr().cast(), iov_len: data.len() };
    // SAFETY: zeroed bytes are a valid `msghdr`, filled below.
    let mut m: libc::msghdr = unsafe { std::mem::zeroed() };
    m.msg_iov = &mut iov;
    m.msg_iovlen = 1;
    m.msg_control = ctl.as_mut_ptr().cast();
    m.msg_controllen = ctl.len() as _;
    let flags = libc::MSG_DONTWAIT | if peek { libc::MSG_PEEK } else { 0 };
    // SAFETY: a valid message of local buffers.
    let n = unsafe { libc::recvmsg(b, &mut m, flags) };
    if n < 0 {
        return None;
    }
    data.truncate(n as usize);
    ctl.truncate(m.msg_controllen as usize);
    Some((data, host_fds(&ctl)))
}

/// Whether `fd` is a bundle: a datagram socket with the bundle's mark.
fn is_bundle(fd: i32) -> bool {
    let opt = |name: libc::c_int| {
        let mut v: libc::c_int = 0;
        let mut l = 4 as libc::socklen_t;
        // SAFETY: valid out-parameters.
        let r = unsafe {
            libc::getsockopt(fd, libc::SOL_SOCKET, name, (&mut v as *mut i32).cast(), &mut l)
        };
        if r == 0 { v } else { -1 }
    };
    opt(libc::SO_TYPE) == libc::SOCK_DGRAM && opt(libc::SO_SNDBUF) == BUNDLE_MARK
}

/// One descriptor a bundle describes.
struct Entry {
    index: usize,
    kind: u8,
    state: Vec<u8>,
    companions: Vec<i32>,
}

/// A bundle's contents: the sender's credentials, if it gave any, and
/// its entries.
struct Manifest {
    creds: Option<Creds>,
    entries: Vec<Entry>,
}

/// Read bundle `b`'s manifest and the descriptors behind its entries.
fn read_bundle(b: i32, peek: bool) -> Option<Manifest> {
    let (data, _) = recv_datagram(b, peek)?;
    let mut d = Dec::new(&data);
    if d.u64() != MAGIC {
        return None;
    }
    let has = d.bool();
    let creds = Creds { host_pid: d.i32(), uid: d.u32(), gid: d.u32() };
    let n = d.count(9);
    let mut entries = Vec::with_capacity(n);
    for _ in 0..n {
        let (index, kind, want) = (d.u32() as usize, d.u8(), d.u32() as usize);
        entries.push(Entry { index, kind, state: d.bytes(), companions: Vec::with_capacity(want) });
    }
    if !d.whole() {
        return None;
    }
    let mut fds = Vec::new();
    let total: usize = entries.iter().map(|e| e.companions.capacity()).sum();
    while fds.len() < total {
        let Some((_, got)) = recv_datagram(b, peek) else { break };
        fds.extend(got);
    }
    let mut fds = fds.into_iter();
    for e in &mut entries {
        let want = e.companions.capacity();
        e.companions.extend(fds.by_ref().take(want));
    }
    Some(Manifest { creds: has.then_some(creds), entries })
}

fn close_all(fds: impl IntoIterator<Item = i32>) {
    for fd in fds {
        // SAFETY: descriptors received for this call, not the guest's.
        unsafe { libc::close(fd) };
    }
}

/// What a received message's host control data gives the guest.
pub struct Incoming {
    /// The descriptors, each taken as what it stands for.
    pub fds: Vec<i32>,
    /// Credentials the sender gave.
    pub creds: Option<Creds>,
    /// Whether descriptors that did not fit were closed.
    pub dropped: bool,
}

/// Take the host control data `ctl` of a received message, keeping at most
/// `room` of its descriptors (the rest are closed): the descriptors and
/// any credentials the sender gave. A bundle is taken and closed;
/// `peek` reads it without taking it from the queue (`MSG_PEEK`).
pub fn receive(ctl: &[u8], room: usize, peek: bool) -> Incoming {
    let mut fds = host_fds(ctl);
    let mut manifest = None;
    if let Some(&b) = fds.last()
        && is_bundle(b)
    {
        manifest = read_bundle(b, peek);
        if manifest.is_some() {
            fds.pop();
            close_all([b]);
        }
    }
    let Some(m) = manifest else {
        let kept = fds.len().min(room);
        let dropped = kept < fds.len();
        close_all(fds.drain(kept..));
        for &fd in &fds {
            crate::net::fresh(fd);
            // A SOCK_SEQPACKET or ping socket of fwe's is one here too.
            crate::net::adopt(fd);
        }
        return Incoming { fds, creds: None, dropped };
    };
    let kept = fds.len().min(room);
    let dropped = kept < fds.len();
    let mut taken = vec![false; fds.len()];
    for e in m.entries {
        match fds.get(e.index) {
            Some(&fd) if e.index < kept => {
                taken[e.index] = import(e.kind, fd, &e.state, e.companions);
            }
            // Not delivered, or not there: what came for it goes.
            _ => close_all(e.companions),
        }
    }
    close_all(fds.drain(kept..));
    for (i, &fd) in fds.iter().enumerate() {
        crate::net::fresh(fd);
        // A socket of a namespace may be a SOCK_SEQPACKET or ping one too.
        if !taken[i] || crate::netns::of(fd).is_some() {
            crate::net::adopt(fd);
        }
    }
    Incoming { fds, creds: m.creds, dropped }
}

/// Linux control data for the guest's buffer of `cap` bytes, as Linux's
/// `scm_recv` writes it: credentials first (when asked for), then the
/// descriptors that fit, close-on-exec if `cloexec`. Returns the bytes and
/// whether anything did not fit (`MSG_CTRUNC`); descriptors that did not
/// fit are closed.
pub fn linux_control(
    cap: usize,
    creds: Option<[u32; 3]>,
    fds: &[i32],
    cloexec: bool,
) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut trunc = false;
    if let Some(c) = creds {
        let mut data = Vec::with_capacity(UCRED);
        for w in c {
            data.extend_from_slice(&w.to_ne_bytes());
        }
        trunc |= put_cmsg(&mut out, cap, SCM_CREDENTIALS, &data);
    }
    if !fds.is_empty() {
        let room = cap.saturating_sub(out.len());
        let fit = if room <= CMSG_HDR { 0 } else { ((room - CMSG_HDR) / 4).min(fds.len()) };
        if fit < fds.len() {
            trunc = true;
            close_all(fds[fit..].iter().copied());
        }
        if fit > 0 {
            let mut data = Vec::with_capacity(4 * fit);
            for &fd in &fds[..fit] {
                if cloexec {
                    // SAFETY: plain host call on a descriptor just received.
                    unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
                }
                data.extend_from_slice(&fd.to_ne_bytes());
            }
            put_cmsg(&mut out, cap, SCM_RIGHTS, &data);
        }
    }
    (out, trunc)
}

/// Append a `SOL_SOCKET` message of `ty` and `data` to `out`, within `cap`
/// bytes in all, as Linux's `put_cmsg`: cut short (and so truncated) when
/// it does not fit, left out when not even its header does. Whether it
/// was truncated.
fn put_cmsg(out: &mut Vec<u8>, cap: usize, ty: i32, data: &[u8]) -> bool {
    let room = cap.saturating_sub(out.len());
    if room < CMSG_HDR {
        return true;
    }
    let len = CMSG_HDR + data.len();
    let mut m = Vec::with_capacity((len + 7) & !7);
    m.extend_from_slice(&(len.min(room) as u64).to_ne_bytes());
    m.extend_from_slice(&(SOL_SOCKET as i32).to_ne_bytes());
    m.extend_from_slice(&ty.to_ne_bytes());
    m.extend_from_slice(data);
    m.resize((len + 7) & !7, 0);
    m.truncate(room);
    out.extend_from_slice(&m);
    len > room
}

/// Check credentials `[pid, uid, gid]` a sender gives (in its pid and user
/// namespaces) as Linux's `scm_check_creds` does: ids its namespace does
/// not map are `EINVAL`; the pid must be its own unless it has
/// `CAP_SYS_ADMIN`, the user id its real, effective or saved one unless it
/// has `CAP_SETUID`, the group id likewise with `CAP_SETGID` (`EPERM`); a
/// pid no process has is `ESRCH`. Returns them as they travel.
pub fn check_creds([pid, uid, gid]: [u32; 3]) -> Result<Creds, i32> {
    let kuid = crate::userns::from_ns(uid, false).filter(|&u| u != u32::MAX);
    let kgid = crate::userns::from_ns(gid, true).filter(|&g| g != u32::MAX);
    let (Some(uid), Some(gid)) = (kuid, kgid) else { return Err(errno::EINVAL) };
    let id = crate::creds::identity();
    let own = pid as i32 == crate::thread::tgid();
    if !((own || id.admin)
        && (id.uids.contains(&uid) || id.setuid)
        && (id.gids.contains(&gid) || id.setgid))
    {
        return Err(errno::EPERM);
    }
    let host_pid = if own {
        crate::host::pid()
    } else {
        crate::pidns::to_host(pid as i32)
            .filter(|&h| crate::host::process_exists(h))
            .ok_or(errno::ESRCH)?
    };
    Ok(Creds { host_pid, uid, gid })
}

/// This process's credentials as Linux attaches them to what it sends
/// when asked: its pid, real user and group ids.
pub fn own_creds() -> Creds {
    let id = crate::creds::identity();
    Creds { host_pid: crate::host::pid(), uid: id.uids[0], gid: id.gids[0] }
}

/// The host addresses (socket paths) of datagram sockets that asked for
/// credentials (`SO_PASSCRED`), which every fwe process sees: a datagram
/// sent to one carries the sender's in a bundle, since the host attaches
/// none (a connected socket's peer is the host's to name).
#[derive(Clone, Default)]
pub struct Passcred {
    paths: std::collections::BTreeSet<Vec<u8>>,
}

impl crate::shared::Data for Passcred {
    fn encode(&self, e: &mut Enc) {
        e.u64(self.paths.len() as u64);
        for p in &self.paths {
            e.bytes(p);
        }
    }
    fn decode(d: &mut Dec) -> Self {
        let n = d.count(8);
        Passcred { paths: (0..n).map(|_| d.bytes()).collect() }
    }
}

fn passcred() -> Option<&'static crate::shared::Record<Passcred>> {
    static R: std::sync::OnceLock<Option<crate::shared::Record<Passcred>>> =
        std::sync::OnceLock::new();
    R.get_or_init(|| crate::shared::Record::named("passcred", 0, Passcred::default).ok()).as_ref()
}

/// The datagram socket at host path `path` asks for credentials (`on`),
/// or no longer does.
pub fn wants_creds(path: &[u8], on: bool) {
    let Some(r) = passcred() else { return };
    if r.get().paths.contains(path) == on {
        return;
    }
    let _ = r.update(|p| {
        if on {
            p.paths.insert(path.to_vec());
        } else {
            p.paths.remove(path);
        }
        Ok(())
    });
}

/// Whether any datagram socket asks for credentials.
pub fn any_wanted() -> bool {
    passcred().is_some_and(|r| !r.get().paths.is_empty())
}

/// Whether the datagram socket at host path `path` asks for credentials.
pub fn creds_wanted(path: &[u8]) -> bool {
    passcred().is_some_and(|r| r.get().paths.contains(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmsg(level: i32, ty: i32, data: &[u8]) -> Vec<u8> {
        let len = CMSG_HDR + data.len();
        let mut c = (len as u64).to_ne_bytes().to_vec();
        c.extend_from_slice(&level.to_ne_bytes());
        c.extend_from_slice(&ty.to_ne_bytes());
        c.extend_from_slice(data);
        c.resize((len + 7) & !7, 0);
        c
    }

    fn ints(v: &[i32]) -> Vec<u8> {
        v.iter().flat_map(|x| x.to_ne_bytes()).collect()
    }

    #[test]
    fn every_rights_message_is_taken() {
        let mut ctl = cmsg(1, SCM_RIGHTS, &ints(&[0]));
        // Another level is passed over.
        ctl.extend(cmsg(41, 50, &[0; 4]));
        ctl.extend(cmsg(1, SCM_RIGHTS, &ints(&[1, 2])));
        assert_eq!(parse(&ctl).unwrap().fds, vec![0, 1, 2]);
    }

    #[test]
    fn bad_messages_are_refused_as_linux_refuses_them() {
        // A length past the buffer, an unknown type, a short ucred, a
        // descriptor that is not open, too many descriptors.
        let mut long = cmsg(1, SCM_RIGHTS, &ints(&[0]));
        long[0] = 64;
        assert_eq!(parse(&long), Err(errno::EINVAL));
        assert_eq!(parse(&cmsg(1, 99, &[])), Err(errno::EINVAL));
        assert_eq!(parse(&cmsg(1, SCM_CREDENTIALS, &[0; 8])), Err(errno::EINVAL));
        assert_eq!(parse(&cmsg(1, SCM_RIGHTS, &ints(&[9999]))), Err(errno::EBADF));
        assert_eq!(parse(&cmsg(1, SCM_RIGHTS, &ints(&[0; 254]))), Err(errno::EINVAL));
        assert_eq!(parse(&cmsg(1, SCM_RIGHTS, &ints(&[0; 253]))).unwrap().fds.len(), 253);
        assert_eq!(
            parse(&cmsg(1, SCM_CREDENTIALS, &ints(&[5, 6, 7]))).unwrap().creds,
            Some([5, 6, 7])
        );
    }

    #[test]
    fn control_written_back_is_cut_as_linux_cuts_it() {
        // Room for the credentials and one descriptor of two.
        // SAFETY: plain host calls.
        let (a, b) = unsafe { (libc::dup(0), libc::dup(0)) };
        let cap = 32 + CMSG_HDR + 4;
        let (out, trunc) = linux_control(cap, Some([1, 2, 3]), &[a, b], false);
        assert!(trunc);
        assert_eq!(out.len(), cap);
        assert_eq!(u64::from_ne_bytes(out[0..8].try_into().unwrap()), 28);
        assert_eq!(u64::from_ne_bytes(out[32..40].try_into().unwrap()), 20);
        // SAFETY: the descriptor kept (the other was closed).
        unsafe { libc::close(a) };
        // No room even for a header: nothing, truncated.
        assert_eq!(linux_control(8, Some([1, 2, 3]), &[], false), (Vec::new(), true));
    }
}
