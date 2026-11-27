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
//! netlink socket, a process descriptor, a file of fwe's file store)
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
//!
//! macOS collects sockets in flight that it finds no process can reach,
//! and empties them (their data and the descriptors queued in them): it
//! looks for references only in sockets that are in flight themselves, so
//! a socket whose sender closed it, passed to a socket that is not in
//! flight, is emptied by any collection that runs before the receiver
//! takes it (one runs whenever a Unix socket goes away). Linux collects
//! only cycles no process can reach. So a message that passes sockets
//! gets a bundle that holds them too (*keeps*), and the sender holds the
//! bundle until its receiver has read it ([`PENDING`]): reachable through
//! it, the sockets are left alone. The receiver closes the keeps as it
//! takes the message, so no reference outlives it.

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
const MAGIC: u64 = 0x6677_655f_7363_6d32;
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
    /// A file of fwe's file store ([`crate::filestore::desc`]).
    pub const STORE: u8 = 7;
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
/// message's length needs to fit (`EINVAL`); messages of other levels are
/// passed over; at `SOL_SOCKET`, `SCM_RIGHTS` adds descriptors (each open,
/// `EBADF`; at most [`SCM_MAX_FD`] in all, `EINVAL`), `SCM_CREDENTIALS`
/// needs to be a whole `ucred`, and any other type is `EINVAL`.
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
    /// The host objects sent in place of descriptors to a process of the
    /// host's ([`prepare`]), closed once sent.
    objects: Vec<std::os::fd::OwnedFd>,
    /// What the store's files described hold them by
    /// ([`crate::filestore::desc::export`]), let go of if the message does
    /// not go.
    stored: Vec<Vec<u8>>,
}

impl Prepared {
    /// The message did not go: its bundle is closed at once, and what it
    /// held of the store's files goes.
    pub fn unsent(mut self) {
        self.objects.clear();
        for fd in self.bundle.take().into_iter().flatten() {
            // SAFETY: the bundle's ends, made by `prepare`.
            unsafe { libc::close(fd) };
        }
        for state in self.stored.drain(..) {
            crate::filestore::desc::unsent(&state);
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

/// The manifests of bundles whose senders ended, or changed program,
/// before their receivers read them ([`settle_pending`]): each by its
/// bundle's host identity, with when it was kept (a count), for the
/// receiver to take ([`take_settled`]). The host collects a bundle held
/// only in flight, emptying it, once its sender no longer holds it.
#[derive(Clone, Default)]
pub struct Settled {
    by_id: std::collections::BTreeMap<u64, (u64, Vec<u8>)>,
    count: u64,
}

/// How many manifests [`Settled`] keeps: the oldest goes for a new one
/// past these (a message never read, its bundle gone with it).
const SETTLED_MOST: usize = 256;

impl crate::shared::Data for Settled {
    fn encode(&self, e: &mut Enc) {
        e.u64(self.count);
        e.u64(self.by_id.len() as u64);
        for (&id, (at, data)) in &self.by_id {
            e.u64(id);
            e.u64(*at);
            e.bytes(data);
        }
    }
    fn decode(d: &mut Dec) -> Self {
        let count = d.u64();
        let n = d.count(24);
        let by_id = (0..n).map(|_| (d.u64(), (d.u64(), d.bytes()))).collect();
        Settled { by_id, count }
    }
}

fn settled() -> Option<&'static crate::shared::Record<Settled>> {
    static R: std::sync::OnceLock<Option<crate::shared::Record<Settled>>> =
        std::sync::OnceLock::new();
    R.get_or_init(|| crate::shared::Record::named("bundles", 0, Settled::default).ok()).as_ref()
}

/// This process ends, or changes program: the manifests of the bundles it
/// sent that their receivers have not read are kept for them
/// ([`Settled`]), taken out of the bundles (first kept, then taken, so a
/// receiver reading at once finds one or the other).
pub fn settle_pending() {
    let p = PENDING.lock().unwrap_or_else(|e| e.into_inner());
    for &b in p.iter() {
        let Some((data, _)) = take_datagram(b, true) else { continue };
        if !data.starts_with(&MAGIC.to_le_bytes()) {
            continue;
        }
        let (Some(r), Some(id)) = (settled(), crate::net::socket_id(b)) else { continue };
        let _ = r.update(|s| {
            s.count += 1;
            let at = s.count;
            s.by_id.insert(id, (at, data));
            while s.by_id.len() > SETTLED_MOST {
                let oldest = s.by_id.iter().min_by_key(|(_, (at, _))| *at).map(|(&id, _)| id);
                oldest.map(|id| s.by_id.remove(&id));
            }
            Ok(())
        });
        if let Some((_, fds)) = recv_datagram(b) {
            close_all(fds);
        }
    }
}

/// The manifest kept of bundle `b` ([`settle_pending`]), taken.
fn take_settled(b: i32) -> Option<Vec<u8>> {
    let r = settled()?;
    if r.get().by_id.is_empty() {
        return None;
    }
    let id = crate::net::socket_id(b)?;
    r.update_maybe(|s| {
        let data = s.by_id.remove(&id).map(|(_, d)| d);
        let changed = data.is_some();
        Ok((data, changed))
    })
    .ok()
    .flatten()
}

/// Bundle `b`'s manifest was read from it: none kept of it stays.
fn forget_settled(b: i32) {
    let Some(r) = settled() else { return };
    if r.get().by_id.is_empty() {
        return;
    }
    if let Some(id) = crate::net::socket_id(b) {
        let _ = r.update_maybe(|s| {
            let changed = s.by_id.remove(&id).is_some();
            Ok(((), changed))
        });
    }
}

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
/// described in a bundle, and the credentials in its manifest. To a
/// process of the host's (`host_peer`), which reads no bundle, a file of
/// fwe's store goes as the host object that holds its data
/// ([`crate::filestore::io::host_object`]).
pub fn prepare(fds: &[i32], creds: Option<Creds>, host_peer: bool) -> Result<Prepared, i32> {
    let mut host: Vec<i32> = fds.to_vec();
    let mut objects = Vec::new();
    if host_peer {
        for slot in host.iter_mut() {
            if let Some(object) = crate::filestore::io::host_object(*slot) {
                let object = object?;
                *slot = std::os::fd::AsRawFd::as_raw_fd(&object);
                objects.push(object);
            }
        }
    }
    let exports: Vec<Option<Export>> = host.iter().map(|&fd| export(fd)).collect();
    let stored = exports
        .iter()
        .flatten()
        .filter(|x| x.kind == kind::STORE)
        .map(|x| x.state.clone())
        .collect();
    // The sockets sent as themselves, kept in the bundle as well, out of
    // the host's collection (a process of the host's reads no bundle).
    let keeps: Vec<i32> = if host_peer {
        Vec::new()
    } else {
        host.iter()
            .zip(&exports)
            .filter(|(_, x)| !x.as_ref().is_some_and(|x| x.placeholder))
            .map(|(&fd, _)| fd)
            .filter(|&fd| is_socket(fd))
            .collect()
    };
    // What fwe keeps of the sockets sent, which they take along.
    let states: Vec<(usize, Vec<u8>)> = if host_peer {
        Vec::new()
    } else {
        fds.iter()
            .enumerate()
            .filter_map(|(i, &fd)| Some((i, crate::sockstate::export(fd)?)))
            .collect()
    };
    let mut p = Prepared { buf: Vec::new(), bundle: None, objects, stored };
    if creds.is_some()
        || exports.iter().any(Option::is_some)
        || !keeps.is_empty()
        || !states.is_empty()
    {
        let ends = match make_bundle() {
            Ok(ends) => ends,
            Err(e) => {
                p.unsent();
                return Err(e);
            }
        };
        p.bundle = Some(ends);
        if let Err(e) = fill_bundle(ends[0], &exports, creds, &keeps, &states) {
            // Nothing went: the bundle and what it held go.
            p.unsent();
            return Err(e);
        }
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
        .or_else(|| crate::filestore::desc::export(fd))
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
        kind::STORE => crate::filestore::desc::import(fd, &mut d),
        _ => false,
    }
}

/// Put `made` (a new host object) at descriptor number `slot`, in place of
/// what is there: whether it was.
pub(crate) fn replace(slot: i32, made: i32) -> bool {
    // SAFETY: plain host calls on descriptors this process holds.
    unsafe {
        // `dup2` clears close-on-exec; the slot keeps the flag it was
        // received with (`MSG_CMSG_CLOEXEC`).
        let flags = libc::fcntl(slot, libc::F_GETFD);
        let r = libc::dup2(made, slot);
        libc::close(made);
        if r == slot && flags > 0 {
            libc::fcntl(slot, libc::F_SETFD, flags);
        }
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

/// Whether host descriptor `fd` is a socket.
fn is_socket(fd: i32) -> bool {
    // SAFETY: zeroed bytes are a valid `stat`, filled by the call.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out-parameter.
    unsafe { libc::fstat(fd, &mut st) == 0 && st.st_mode & libc::S_IFMT == libc::S_IFSOCK }
}

/// Write the manifest of `exports`, `creds` and `keeps` to bundle end `w`,
/// then the descriptors behind the exports, then the keeps.
fn fill_bundle(
    w: i32,
    exports: &[Option<Export>],
    creds: Option<Creds>,
    keeps: &[i32],
    states: &[(usize, Vec<u8>)],
) -> Result<(), i32> {
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
    e.u32(keeps.len() as u32);
    e.u64(states.len() as u64);
    for (i, s) in states {
        e.u32(*i as u32);
        e.bytes(s);
    }
    let manifest = e.into_bytes();
    send_datagram(w, &manifest, &[])?;
    for chunk in companions.chunks(CHUNK).chain(keeps.chunks(CHUNK)) {
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
fn recv_datagram(b: i32) -> Option<(Vec<u8>, Vec<i32>)> {
    take_datagram(b, false)
}

/// [`recv_datagram`], or a look at the datagram that leaves it there
/// (`peek`, which gives no descriptors).
fn take_datagram(b: i32, peek: bool) -> Option<(Vec<u8>, Vec<i32>)> {
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

/// A bundle's contents: the sender's credentials, if it gave any, its
/// entries, and the states of sockets sent ([`crate::sockstate`]), by
/// index.
struct Manifest {
    creds: Option<Creds>,
    entries: Vec<Entry>,
    states: Vec<(usize, Vec<u8>)>,
}

/// Read bundle `b`'s manifest and the descriptors behind its entries.
fn read_bundle(b: i32) -> Option<Manifest> {
    // The manifest, first; or, its sender having taken it out as it ended
    // ([`settle_pending`]), what it kept of it, the first datagram then
    // holding descriptors.
    let first = recv_datagram(b);
    let (data, mut fds) = match first {
        Some((data, _)) if data.starts_with(&MAGIC.to_le_bytes()) => {
            forget_settled(b);
            (data, Vec::new())
        }
        other => (take_settled(b)?, other.map(|(_, fds)| fds).unwrap_or_default()),
    };
    let mut d = Dec::new(&data);
    if d.u64() != MAGIC {
        close_all(fds);
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
    let keeps = d.u32() as usize;
    let n = d.count(12);
    let states = (0..n).map(|_| (d.u32() as usize, d.bytes())).collect();
    if !d.whole() {
        close_all(fds);
        return None;
    }
    let total: usize = entries.iter().map(|e| e.companions.capacity()).sum();
    while fds.len() < total + keeps {
        let Some((_, got)) = recv_datagram(b) else { break };
        fds.extend(got);
    }
    // The keeps did their part: the message is the receiver's.
    close_all(fds.split_off(total.min(fds.len())));
    let mut fds = fds.into_iter();
    for e in &mut entries {
        let want = e.companions.capacity();
        e.companions.extend(fds.by_ref().take(want));
    }
    Some(Manifest { creds: has.then_some(creds), entries, states })
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
/// any credentials the sender gave. A bundle is taken and closed. A peek
/// (`peek`, `MSG_PEEK`) takes nothing: macOS gives no descriptors on one
/// (its control data has only zeroes where they would be), so the
/// message's descriptors and bundle wait for the receive that takes it.
pub fn receive(ctl: &[u8], room: usize, peek: bool) -> Incoming {
    if peek {
        return Incoming { fds: Vec::new(), creds: None, dropped: false };
    }
    // Received without the kernel lock: where a plug put them, in the
    // guest's range once it is gone.
    let mut fds: Vec<i32> = host_fds(ctl).into_iter().map(crate::fdtable::into_range).collect();
    let mut manifest = None;
    if let Some(&b) = fds.last()
        && is_bundle(b)
    {
        // Fwe's, never the guest's, whatever it held.
        manifest = read_bundle(b);
        fds.pop();
        close_all([b]);
        if manifest.is_none() && crate::trace::file().is_some() {
            crate::trace::note_to_file(&format!(
                "a received message's bundle held no manifest: its {} descriptors are \
                 taken as host objects",
                fds.len()
            ));
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
                if !taken[e.index] && crate::trace::file().is_some() {
                    crate::trace::note_to_file(&format!(
                        "received descriptor {} (kind {}) was not taken as what it stands for",
                        e.index, e.kind
                    ));
                }
            }
            // Not delivered, or not there: what came for it goes.
            _ => close_all(e.companions),
        }
    }
    close_all(fds.drain(kept..));
    for (i, &fd) in fds.iter().enumerate() {
        crate::net::fresh(fd);
        // A socket of a namespace can be a SOCK_SEQPACKET or ping one too.
        if !taken[i] || crate::netns::of(fd).is_some() {
            crate::net::adopt(fd);
        }
    }
    for (i, s) in &m.states {
        if let Some(&fd) = fds.get(*i) {
            crate::sockstate::import(fd, s);
            crate::net::received(fd);
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
/// not map are `EINVAL`; the pid needs to be its own unless it has
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
            .filter(|&h| crate::host::probe(h).exists())
            .ok_or(errno::ESRCH)?
    }
    .get();
    Ok(Creds { host_pid, uid, gid })
}

/// This process's credentials as Linux attaches them to what it sends
/// when asked: its pid, real user and group ids.
pub fn own_creds() -> Creds {
    let id = crate::creds::identity();
    Creds { host_pid: crate::host::pid().get(), uid: id.uids[0], gid: id.gids[0] }
}

/// The Unix sockets that asked for credentials (`SO_PASSCRED`), which
/// every fwe process sees, since the host attaches none: the host
/// addresses (socket paths) of datagram sockets, a datagram sent to one
/// carrying the sender's in a bundle, and the host identities of sockets
/// (`net::socket_ids`), to which a process not the maker of its end of the
/// connection sends its own (Linux gives each message's sender; the
/// receiver takes the end's maker otherwise). Each with the processes that
/// hold it (a host pid and start time): it asks until the last of them
/// closes it or ends.
#[derive(Clone, Default)]
pub struct Passcred {
    paths: std::collections::BTreeMap<Vec<u8>, Vec<(i32, u64)>>,
    socks: std::collections::BTreeMap<u64, Vec<(i32, u64)>>,
}

fn encode_holders(e: &mut Enc, h: &[(i32, u64)]) {
    e.u64(h.len() as u64);
    for &(pid, start) in h {
        e.i32(pid);
        e.u64(start);
    }
}

fn decode_holders(d: &mut Dec) -> Vec<(i32, u64)> {
    let n = d.count(12);
    (0..n).map(|_| (d.i32(), d.u64())).collect()
}

impl crate::shared::Data for Passcred {
    fn encode(&self, e: &mut Enc) {
        e.u64(self.paths.len() as u64);
        for (p, h) in &self.paths {
            e.bytes(p);
            encode_holders(e, h);
        }
        e.u64(self.socks.len() as u64);
        for (&s, h) in &self.socks {
            e.u64(s);
            encode_holders(e, h);
        }
    }
    fn decode(d: &mut Dec) -> Self {
        let n = d.count(12);
        let paths = (0..n).map(|_| (d.bytes(), decode_holders(d))).collect();
        let n = d.count(16);
        let socks = (0..n).map(|_| (d.u64(), decode_holders(d))).collect();
        Passcred { paths, socks }
    }
}

fn passcred() -> Option<&'static crate::shared::Record<Passcred>> {
    static R: std::sync::OnceLock<Option<crate::shared::Record<Passcred>>> =
        std::sync::OnceLock::new();
    R.get_or_init(|| crate::shared::Record::named("passcred", 0, Passcred::default).ok()).as_ref()
}

/// A socket that asks for credentials, named by its path or identity.
#[derive(Clone, Copy)]
pub enum Asker<'a> {
    Path(&'a [u8]),
    Sock(u64),
}

/// This process as a holder.
fn me() -> (i32, u64) {
    (crate::host::pid().get(), crate::procreg::own_start().unwrap_or(0))
}

/// The holders of `a` in `p`, made if `make`.
fn holders<'p>(p: &'p mut Passcred, a: Asker, make: bool) -> Option<&'p mut Vec<(i32, u64)>> {
    match a {
        Asker::Path(path) if make => Some(p.paths.entry(path.to_vec()).or_default()),
        Asker::Path(path) => p.paths.get_mut(path),
        Asker::Sock(id) if make => Some(p.socks.entry(id).or_default()),
        Asker::Sock(id) => p.socks.get_mut(&id),
    }
}

fn remove(p: &mut Passcred, a: Asker) {
    match a {
        Asker::Path(path) => p.paths.remove(path),
        Asker::Sock(id) => p.socks.remove(&id),
    };
}

/// The socket `a` asks for credentials (`on`, this process holding it),
/// or no longer does (for every process).
pub fn wants_creds(a: Asker, on: bool) {
    let Some(r) = passcred() else { return };
    let me = me();
    let _ = r.update_maybe(|p| {
        let changed = match holders(p, a, on) {
            Some(h) if on && !h.contains(&me) => {
                h.push(me);
                true
            }
            Some(_) if !on => {
                remove(p, a);
                true
            }
            _ => false,
        };
        Ok(((), changed))
    });
}

/// This process holds socket `a`, which asks for credentials, too (a fork
/// child, or one it was passed to).
pub fn holds(a: Asker) {
    wants_creds(a, true);
}

/// This process no longer holds socket `a` (its last descriptor here is
/// closed): with its last holder, it no longer asks.
pub fn released(a: Asker) {
    let Some(r) = passcred() else { return };
    let me = me();
    let _ = r.update_maybe(|p| {
        let Some(h) = holders(p, a, false) else { return Ok(((), false)) };
        let before = h.len();
        h.retain(|&x| x != me);
        let changed = h.len() != before;
        if h.is_empty() {
            remove(p, a);
        }
        Ok(((), changed))
    });
}

/// Whether socket `a` asks for credentials: some process that holds it is
/// alive.
pub fn creds_wanted(a: Asker) -> bool {
    let Some(r) = passcred() else { return false };
    let p = r.get();
    let h = match a {
        Asker::Path(path) => p.paths.get(path),
        Asker::Sock(id) => p.socks.get(&id),
    };
    h.is_some_and(|h| h.iter().any(|&x| crate::procreg::alive_kept(x)))
}

/// The record's generation, which changes with what asks.
pub fn generation() -> u64 {
    passcred().map_or(0, |r| r.generation())
}

/// Whether any socket asks for credentials: an answer kept until the
/// record changes, so that a write that need not look further costs two
/// atomic loads.
pub fn any_wanted() -> bool {
    use std::sync::atomic::{AtomicU64, Ordering};
    // The generation the answer is of, +1 (0: none yet), shifted left by
    // one, with the answer in the low bit: one word, so that the two go
    // together.
    static KEPT: AtomicU64 = AtomicU64::new(0);
    let Some(r) = passcred() else { return false };
    let now = (r.generation() + 1) << 1;
    let kept = KEPT.load(Ordering::Relaxed);
    if kept & !1 == now {
        return kept & 1 != 0;
    }
    let p = r.get();
    let any = !p.paths.is_empty() || !p.socks.is_empty();
    KEPT.store(now | any as u64, Ordering::Relaxed);
    any
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::Data;

    #[test]
    fn what_asks_for_credentials_survives_its_encoding() {
        let mut p = Passcred::default();
        p.paths.insert(b"/tmp/s".to_vec(), vec![(7, 70)]);
        p.socks.insert(0xfeed, vec![(7, 70), (8, 80)]);
        let mut e = Enc::new();
        p.encode(&mut e);
        let b = e.into_bytes();
        let mut d = Dec::new(&b);
        let q = Passcred::decode(&mut d);
        assert!(d.whole());
        assert_eq!((q.paths, q.socks), (p.paths, p.socks));
    }

    #[test]
    fn kept_manifests_survive_their_encoding() {
        let mut s = Settled { count: 3, ..Settled::default() };
        s.by_id.insert(0xbeef, (3, vec![1, 2, 3]));
        let mut e = Enc::new();
        s.encode(&mut e);
        let b = e.into_bytes();
        let mut d = Dec::new(&b);
        let t = Settled::decode(&mut d);
        assert!(d.whole());
        assert_eq!((t.count, t.by_id), (s.count, s.by_id));
    }

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
