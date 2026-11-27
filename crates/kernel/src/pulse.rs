//! The Mac's PulseAudio server for Linux programs.
//!
//! The server named by fwe's own `PULSE_SERVER` (a Unix socket, `unix:PATH`
//! or `PATH`), or else the one PulseAudio's library on the Mac finds by
//! default (`.config/pulse/HOST-runtime/native` in the user's home,
//! [`server`]), is the guest's system-wide server. A Unix socket the
//! guest connects by the system server's name, `/run/pulse/native` or
//! `/var/run/pulse/native`, reaches it ([`host_socket`]). Linux's libpulse
//! tries that name last, and the guest's `PULSE_SERVER` is
//! `unix:/run/pulse/native` where fwe's names a server ([`GUEST_SERVER`]).
//!
//! Such a socket's first packet from the client, its `AUTH` command
//! ([`Auth`]), is sent with two changes ([`write`]):
//! - **the Mac user's cookie** (`PULSE_COOKIE`, or `.config/pulse/cookie`
//!   in the home, [`cookie_file`]) for the guest's: on macOS the server
//!   knows its clients only by the cookie (Linux's also takes the
//!   socket's credentials), and the guest's is a file of its own root's;
//! - **no offer of shared memory:** a guest's POSIX segments are files in
//!   its root's `/dev/shm`, and its memfds are none the Mac's server can
//!   map. The sound then travels over the socket.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

/// The guest's `PULSE_SERVER`, where fwe's environment names one.
pub const GUEST_SERVER: &[u8] = b"unix:/run/pulse/native";

/// The guest names of the Mac's server's socket.
const GUEST_SOCKETS: [&[u8]; 2] = [b"/run/pulse/native", b"/var/run/pulse/native"];

/// The Mac's server as fwe's environment named it: its socket (a host
/// path; `None` for the one the Mac's library finds), and its cookie's
/// file (`None` for the user's).
struct Named {
    server: Option<Vec<u8>>,
    cookie: Option<Vec<u8>>,
}

static NAMED: OnceLock<Named> = OnceLock::new();
/// The Mac's server's socket, found as first needed ([`server`]).
static SERVER: OnceLock<Option<Vec<u8>>> = OnceLock::new();

/// The Mac's server is at socket `server`, and its user's cookie in file
/// `cookie` (host paths, as the first fwe's environment named them,
/// [`named_server`]; `None` for the server and cookie the Mac's PulseAudio
/// library finds, [`server`], [`cookie_file`]). Set as fwe starts, and
/// passed on to the fwe a guest's `execve` starts ([`host_server`],
/// [`host_cookie`]).
pub fn set_host(server: Option<&[u8]>, cookie: Option<&[u8]>) {
    let named = |p: Option<&[u8]>| p.filter(|p| !p.is_empty()).map(<[u8]>::to_vec);
    let _ = NAMED.set(Named { server: named(server), cookie: named(cookie) });
}

/// The server fwe's environment named, to pass on.
pub fn host_server() -> Option<&'static [u8]> {
    NAMED.get().and_then(|n| n.server.as_deref())
}

/// The cookie's file fwe's environment named, to pass on.
pub fn host_cookie() -> Option<&'static [u8]> {
    NAMED.get().and_then(|n| n.cookie.as_deref())
}

/// The Unix socket `PULSE_SERVER` value `named` names (`unix:PATH` or
/// `PATH`): `None` for a server named otherwise (over TCP), which the
/// guest reaches as the Mac does.
pub fn named_server(named: &[u8]) -> Option<Vec<u8>> {
    let path = named.strip_prefix(b"unix:").unwrap_or(named);
    path.starts_with(b"/").then(|| path.to_vec())
}

/// The Mac's server's socket: the one named, or the one PulseAudio's
/// library on the Mac connects to by default
/// (`.config/pulse/HOST-runtime/native` in the user's home).
fn server() -> Option<&'static [u8]> {
    SERVER
        .get_or_init(|| {
            if let Some(named) = host_server() {
                return Some(named.to_vec());
            }
            let mut host = [0u8; 256];
            // SAFETY: a buffer of its length; the host NUL-terminates what
            // fits.
            if unsafe { libc::gethostname(host.as_mut_ptr().cast(), host.len()) } != 0 {
                return None;
            }
            let host = host.split(|&b| b == 0).next().unwrap_or_default();
            let home = crate::host::user_home()?;
            Some([home, b"/.config/pulse/", host, b"-runtime/native"].concat())
        })
        .as_deref()
}

/// The file of the Mac user's cookie: the one named (`PULSE_COOKIE`), or
/// `.config/pulse/cookie` in the home, as PulseAudio's library finds it.
fn cookie_file() -> Option<Vec<u8>> {
    if let Some(file) = host_cookie() {
        return Some(file.to_vec());
    }
    Some([crate::host::user_home()?, b"/.config/pulse/cookie"].concat())
}

/// The host socket a guest Unix socket name stands for, if it names the
/// Mac's server.
pub fn host_socket(name: &[u8]) -> Option<Vec<u8>> {
    if !GUEST_SOCKETS.contains(&name) || NAMED.get().is_none() {
        return None;
    }
    server().map(<[u8]>::to_vec)
}

/// Whether host path `path` is the Mac's server's socket (once a guest
/// has named it: the socket is found only then).
pub fn is_host_socket(path: &[u8]) -> bool {
    SERVER.get().and_then(Option::as_deref).is_some_and(|s| s == path)
}

/// A cookie's length, as the protocol sends it.
const COOKIE_LEN: usize = 256;

/// The client's first packet, `AUTH`: a packet's descriptor (its length,
/// channel `!0` for a command, offsets and flags: five big-endian words),
/// then a tag structure: the command (`L` 8), its tag (`L`), the
/// protocol version (`L`, whose top bits offer shared memory and memfds)
/// and the cookie (`x`, 256 bytes).
struct Auth;

impl Auth {
    const LEN: usize = 20 + 5 + 5 + 5 + 5 + COOKIE_LEN;
    /// The version word's top byte, and the bits offering POSIX shared
    /// memory (`0x80`) and memfds (`0x40`).
    const VERSION_TOP: usize = 31;
    const SHM_OFFERS: u8 = 0xc0;
    const COOKIE_AT: usize = 40;

    /// Whether byte `k` of a packet's first bytes `seen` (`seen[k]`
    /// the one in question) is as an `AUTH` packet's: the parts of it
    /// that are known before the version and the cookie.
    fn fits(seen: &[u8], k: usize) -> bool {
        let payload = (Self::LEN - 20) as u32;
        let known: Option<u8> = match k {
            0..4 => Some(payload.to_be_bytes()[k]),
            4..8 => Some(0xff),
            8..20 => Some(0),
            20 | 30 => Some(b'L'),
            21..25 => Some(8u32.to_be_bytes()[k - 21]),
            25 => Some(b'L'),
            35 => Some(b'x'),
            36..40 => Some((COOKIE_LEN as u32).to_be_bytes()[k - 36]),
            _ => None,
        };
        known.is_none_or(|b| seen[k] == b)
    }
}

/// What fwe knows of a connection to the Mac's server: the bytes the client
/// has sent of its first packet, while it is being sent and is an
/// `AUTH`; the cookie it goes with.
struct Conn {
    seen: Vec<u8>,
    cookie: Option<[u8; COOKIE_LEN]>,
}

/// The connections to the Mac's server whose first packet is being sent,
/// by socket (its inode).
static CONNS: Mutex<Option<HashMap<u64, Conn>>> = Mutex::new(None);

/// Whether one is: until then a write is not looked at.
static ANY: AtomicBool = AtomicBool::new(false);

fn inode(fd: i32) -> Option<u64> {
    // SAFETY: an all-zero `stat` is a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `st` is a valid out-parameter.
    (unsafe { libc::fstat(fd, &mut st) } == 0).then_some(st.st_ino)
}

/// The Mac user's cookie, as its file holds it now.
fn cookie() -> Option<[u8; COOKIE_LEN]> {
    use std::os::unix::ffi::OsStrExt;
    let file = std::fs::read(std::ffi::OsStr::from_bytes(&cookie_file()?)).ok()?;
    file.get(..COOKIE_LEN)?.try_into().ok()
}

/// Socket `fd` is now connected to the Mac's server.
pub fn connected(fd: i32) {
    let Some(ino) = inode(fd) else { return };
    ANY.store(true, Ordering::Relaxed);
    let mut c = CONNS.lock().unwrap_or_else(|e| e.into_inner());
    c.get_or_insert_with(HashMap::new).insert(ino, Conn { seen: Vec::new(), cookie: cookie() });
}

/// The `k`th byte of the host buffers `iov`.
fn byte_of(iov: &[libc::iovec], mut k: usize) -> u8 {
    for v in iov {
        if k < v.iov_len {
            // SAFETY: `k` is within this buffer, a checked host one.
            return unsafe { *(v.iov_base as *const u8).add(k) };
        }
        k -= v.iov_len;
    }
    0
}

/// `bytes`, the client's next, as they go to the server: those of an
/// `AUTH` packet's version and cookie changed ([`Auth`]); `seen` the
/// packet's bytes sent before them. Stops following where the packet is
/// not an `AUTH` (`false`).
fn changed(seen: &mut Vec<u8>, cookie: Option<&[u8; COOKIE_LEN]>, bytes: &mut [u8]) -> bool {
    for b in bytes.iter_mut() {
        let k = seen.len();
        if k >= Auth::LEN {
            break;
        }
        seen.push(*b);
        if !Auth::fits(seen, k) {
            return false;
        }
        if k == Auth::VERSION_TOP {
            *b &= !Auth::SHM_OFFERS;
        } else if let Some(c) = cookie.filter(|_| k >= Auth::COOKIE_AT) {
            *b = c[k - Auth::COOKIE_AT];
        }
    }
    true
}

/// A send of host buffers `iov` on socket `fd`, if it is a connection to
/// the Mac's server whose first packet is still going: sent by `send` (the
/// send the guest made, of the buffers given it) as [`changed`] makes it.
/// `None` for any other socket, and once the first packet has gone.
pub fn write(
    fd: i32,
    iov: &[libc::iovec],
    mut send: impl FnMut(&[libc::iovec]) -> i64,
) -> Option<i64> {
    if !ANY.load(Ordering::Relaxed) {
        return None;
    }
    let ino = inode(fd)?;
    let mut c = CONNS.lock().unwrap_or_else(|e| e.into_inner());
    let conns = c.as_mut()?;
    let conn = conns.get_mut(&ino)?;
    let total: usize = iov.iter().map(|v| v.iov_len).sum();
    let before = conn.seen.len();
    // As far as the first packet goes (a short send, which the client
    // sends the rest of after); what follows it as any write is.
    let mut bytes: Vec<u8> = (0..total.min(Auth::LEN - before)).map(|k| byte_of(iov, k)).collect();
    let mut seen = conn.seen.clone();
    if !changed(&mut seen, conn.cookie.as_ref(), &mut bytes) {
        conns.remove(&ino);
        return None;
    }
    let part = [libc::iovec { iov_base: bytes.as_mut_ptr().cast(), iov_len: bytes.len() }];
    let r = send(&part);
    if r > 0 {
        // The bytes the host took: the rest are sent (and changed) again.
        conn.seen = seen[..before + r as usize].to_vec();
        if conn.seen.len() >= Auth::LEN {
            conns.remove(&ino);
        }
    }
    Some(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An `AUTH` packet with version `version` and cookie byte `c`.
    fn auth(version: u32, c: u8) -> Vec<u8> {
        let mut p = ((Auth::LEN - 20) as u32).to_be_bytes().to_vec();
        p.extend([0xff; 4]);
        p.extend([0; 12]);
        p.push(b'L');
        p.extend(8u32.to_be_bytes());
        p.push(b'L');
        p.extend(7u32.to_be_bytes());
        p.push(b'L');
        p.extend(version.to_be_bytes());
        p.push(b'x');
        p.extend((COOKIE_LEN as u32).to_be_bytes());
        p.extend([c; COOKIE_LEN]);
        assert_eq!(p.len(), Auth::LEN);
        p
    }

    #[test]
    fn auth_goes_with_the_macs_cookie_and_no_shared_memory() {
        let cookie = [9u8; COOKIE_LEN];
        let mut packet = auth(0xc000_0023, 1);
        let mut seen = Vec::new();
        assert!(changed(&mut seen, Some(&cookie), &mut packet));
        assert_eq!(packet, auth(0x0000_0023, 9));
        // In pieces, as a client can write it.
        let mut packet = auth(0x8000_0023, 1);
        let mut seen = Vec::new();
        for piece in packet.chunks_mut(17) {
            assert!(changed(&mut seen, Some(&cookie), piece));
        }
        assert_eq!(packet, auth(0x0000_0023, 9));
        // Without a cookie of the Mac's, the client's goes.
        let mut packet = auth(0x8000_0023, 1);
        assert!(changed(&mut Vec::new(), None, &mut packet));
        assert_eq!(packet, auth(0x23, 1));
    }

    #[test]
    fn a_first_packet_other_than_auth_goes_as_it_is() {
        let mut packet = auth(0xc000_0023, 1);
        packet[24] = 9;
        assert!(!changed(&mut Vec::new(), Some(&[0; COOKIE_LEN]), &mut packet.clone()));
    }

    #[test]
    fn a_server_named_by_its_unix_socket() {
        assert_eq!(
            named_server(b"unix:/tmp/pulse-x/native"),
            Some(b"/tmp/pulse-x/native".to_vec())
        );
        assert_eq!(named_server(b"/p/native"), Some(b"/p/native".to_vec()));
        assert_eq!(named_server(b"tcp:localhost"), None);
    }
}
