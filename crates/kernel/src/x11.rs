//! The host's X display for Linux programs.
//!
//! The display fwe's own `DISPLAY` names (`:N`, Xvfb's or Xorg's socket
//! `/tmp/.X11-unix/XN`; or XQuartz's launchd socket, `/private/tmp/…:N`) is
//! the guest's display `N`: a Unix socket the guest connects to by that
//! display's name, `/tmp/.X11-unix/XN` or the abstract name Linux's libxcb
//! tries first, reaches the host server's socket ([`host_socket`]). The
//! guest's `DISPLAY` is `:N` ([`guest_display`]). Other displays are the
//! guest's own, in its root (an X server it runs itself, as Xwayland).
//!
//! Such a socket is an X connection ([`connected`]), whose requests fwe
//! follows as the client writes them ([`Stream`]): the connection's setup
//! (its authorization), then each request's header and length. MIT-SHM's
//! `ShmAttach` names a System V segment by id, which the host server would
//! look up among the host's segments; fwe's segments are files of its own
//! ([`crate::sysvipc`]). So a `ShmAttach` is sent as `ShmAttachFd` (MIT-SHM
//! 1.2), passing the segment's file, which the server maps as the guest
//! has: the images the guest draws in it are the server's too, uncopied.
//! The extension's request number, and whether the server takes
//! descriptors, fwe asks the server once, on a connection of its own with
//! the guest's authorization ([`query_shm`]).

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// MIT-SHM's minor request numbers.
const SHM_ATTACH: u8 = 1;
const SHM_ATTACH_FD: u8 = 6;
/// The length of a `ShmAttach` request.
const SHM_ATTACH_LEN: u64 = 16;

/// The host display fwe's `DISPLAY` names: its number, and its socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Display {
    pub number: u32,
    pub socket: Vec<u8>,
}

/// The display `value` (a `DISPLAY`) names on this host, if it is a local
/// one reached by a Unix socket: `:N`, `unix:N` (`/tmp/.X11-unix/XN`) or a
/// launchd socket's path, `/path:N` (XQuartz's); a screen after a `.` is
/// the guest's to pick.
pub fn parse(value: &[u8]) -> Option<Display> {
    let colon = value.iter().rposition(|&b| b == b':')?;
    let (host, rest) = (&value[..colon], &value[colon + 1..]);
    let digits = rest.split(|&b| b == b'.').next()?;
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let number: u32 = std::str::from_utf8(digits).ok()?.parse().ok()?;
    let socket = match host {
        b"" | b"unix" => format!("/tmp/.X11-unix/X{number}").into_bytes(),
        h if h.starts_with(b"/") => h.to_vec(),
        _ => return None,
    };
    Some(Display { number, socket })
}

/// The guest's `DISPLAY` for the host's `value`: `:N` (with its screen)
/// for a launchd socket's path, which Linux's libxcb does not read;
/// otherwise `value` as it is.
pub fn guest_display(value: &[u8]) -> Vec<u8> {
    match parse(value) {
        Some(_) if value.starts_with(b"/") => {
            let colon = value.iter().rposition(|&b| b == b':').unwrap_or(0);
            value[colon..].to_vec()
        }
        _ => value.to_vec(),
    }
}

/// The host display: as `DISPLAY` names it, and the display.
static HOST: OnceLock<Option<(Vec<u8>, Display)>> = OnceLock::new();

/// The host display is the one `value` (fwe's `DISPLAY` as the first fwe
/// was given it) names, if any; set as fwe starts, and passed on to the
/// fwe a guest's `execve` starts ([`host_value`]), whose environment is
/// the guest's.
pub fn set_host(value: Option<&[u8]>) {
    let _ = HOST.set(value.and_then(|v| parse(v).map(|d| (v.to_vec(), d))));
}

/// The host display's `DISPLAY`, to pass on.
pub fn host_value() -> Option<&'static [u8]> {
    HOST.get().and_then(Option::as_ref).map(|(v, _)| &v[..])
}

fn host_display() -> Option<&'static Display> {
    HOST.get().and_then(Option::as_ref).map(|(_, d)| d)
}

/// The host socket a guest Unix socket name stands for, if it names the
/// host display: `name` is a path, or an abstract name without its
/// leading NUL.
pub fn host_socket(name: &[u8]) -> Option<Vec<u8>> {
    let d = host_display()?;
    (name == format!("/tmp/.X11-unix/X{}", d.number).as_bytes()).then(|| d.socket.clone())
}

/// Whether host path `path` is the host display's socket.
pub fn is_host_socket(path: &[u8]) -> bool {
    host_display().is_some_and(|d| d.socket == path)
}

/// Where a connection's client is in what it sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// The setup's fixed 12 bytes.
    SetupHead,
    /// The setup's authorization name and data, of these lengths (each
    /// padded to 4 bytes).
    SetupBody {
        name: usize,
        data: usize,
    },
    Requests,
}

/// A request the client sends, as [`Stream::walk`] meets its header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Request {
    /// Where it starts in the bytes walked (`None`: in earlier ones).
    at: Option<u64>,
    major: u8,
    minor: u8,
    /// Its length in bytes.
    len: u64,
}

/// What [`Stream::walk`] does at a request.
#[derive(Debug, PartialEq, Eq)]
enum Flow {
    Pass,
    /// Stop before it, if it starts in the bytes walked.
    Stop,
}

/// The requests a client has sent on an X connection, as far as their
/// framing: the header being gathered, and what is still to come of the
/// current request.
#[derive(Debug, Clone)]
pub struct Stream {
    phase: Phase,
    /// The bytes of a header (or of the setup's body) gathered so far.
    head: Vec<u8>,
    /// Bytes of the current request still to pass.
    skip: u64,
    big_endian: bool,
    /// The setup's authorization: its name and data.
    auth: Option<(Vec<u8>, Vec<u8>)>,
}

impl Default for Stream {
    fn default() -> Self {
        Stream { phase: Phase::SetupHead, head: Vec::new(), skip: 0, big_endian: false, auth: None }
    }
}

fn pad4(n: usize) -> usize {
    (n + 3) & !3
}

/// Where in some bytes a `ShmAttach` is ([`Stream::find_attach`]).
#[derive(Debug, PartialEq, Eq)]
enum Found {
    None,
    /// Whole, starting here.
    Whole(u64),
    /// Starting here, its end past the bytes.
    Cut(u64),
}

impl Stream {
    fn u16_at(&self, at: usize) -> u64 {
        let v = [self.head[at], self.head[at + 1]];
        u64::from(if self.big_endian { u16::from_be_bytes(v) } else { u16::from_le_bytes(v) })
    }

    fn u32_at(&self, at: usize) -> u64 {
        let h = &self.head;
        let v = [h[at], h[at + 1], h[at + 2], h[at + 3]];
        u64::from(if self.big_endian { u32::from_be_bytes(v) } else { u32::from_le_bytes(v) })
    }

    /// The bytes the header being gathered takes.
    fn wanted(&self) -> usize {
        match self.phase {
            Phase::SetupHead => 12,
            Phase::SetupBody { name, data } => pad4(name) + pad4(data),
            // BIG-REQUESTS: a length of 0, the length's 32 bits next.
            Phase::Requests if self.head.len() >= 4 && self.u16_at(2) == 0 => 8,
            Phase::Requests => 4,
        }
    }

    /// Walk `len` bytes (`byte(k)` the `k`th) as the client's next, calling
    /// `at` at each request once its header is whole. Returns the bytes
    /// walked (fewer than `len` where `at` stopped), and where in them a
    /// header they end in the middle of began.
    fn walk(
        &mut self,
        len: u64,
        byte: impl Fn(u64) -> u8,
        mut at: impl FnMut(&Request) -> Flow,
    ) -> (u64, Option<u64>) {
        // Where the header being gathered began in these bytes.
        let mut from = None;
        let mut k = 0;
        while k < len {
            if self.skip > 0 {
                let n = self.skip.min(len - k);
                self.skip -= n;
                k += n;
                continue;
            }
            if self.head.is_empty() {
                from = Some(k);
            }
            self.head.push(byte(k));
            k += 1;
            if self.head.len() < self.wanted() {
                continue;
            }
            match self.phase {
                Phase::SetupHead => {
                    self.big_endian = self.head[0] == b'B';
                    let (name, data) = (self.u16_at(6) as usize, self.u16_at(8) as usize);
                    self.phase = Phase::SetupBody { name, data };
                    if name == 0 && data == 0 {
                        self.auth = Some((Vec::new(), Vec::new()));
                        self.phase = Phase::Requests;
                    }
                }
                Phase::SetupBody { name, data } => {
                    let d = pad4(name);
                    self.auth = Some((self.head[..name].to_vec(), self.head[d..d + data].to_vec()));
                    self.phase = Phase::Requests;
                }
                Phase::Requests => {
                    let header = self.head.len() as u64;
                    let words = self.u16_at(2);
                    let total = if words == 0 { 4 * self.u32_at(4) } else { 4 * words };
                    let req =
                        Request { at: from, major: self.head[0], minor: self.head[1], len: total };
                    if at(&req) == Flow::Stop
                        && let Some(s) = from
                    {
                        self.head.clear();
                        return (s, None);
                    }
                    self.skip = total.saturating_sub(header);
                }
            }
            self.head.clear();
            from = None;
        }
        let partial =
            (self.phase == Phase::Requests && !self.head.is_empty()).then_some(from).flatten();
        (len, partial)
    }

    /// Where the first `ShmAttach` (of MIT-SHM's request number `major`)
    /// starts in the client's next `len` bytes; one whose start was in
    /// bytes already sent is not looked for.
    fn find_attach(&self, len: u64, byte: impl Fn(u64) -> u8, major: u8) -> Found {
        let mut s = self.clone();
        let mut found = None;
        let (_, partial) = s.walk(len, &byte, |r| {
            if r.major == major
                && r.minor == SHM_ATTACH
                && r.len == SHM_ATTACH_LEN
                && r.at.is_some()
            {
                found = r.at;
                Flow::Stop
            } else {
                Flow::Pass
            }
        });
        match (found, partial) {
            (Some(a), _) if a + SHM_ATTACH_LEN <= len => Found::Whole(a),
            (Some(a), _) => Found::Cut(a),
            (None, Some(p)) if byte(p) == major => Found::Cut(p),
            _ => Found::None,
        }
    }

    /// The client sent `len` more bytes.
    fn advance(&mut self, len: u64, byte: impl Fn(u64) -> u8) {
        self.walk(len, byte, |_| Flow::Pass);
    }
}

/// What fwe knows of an X connection: the server's socket, and the
/// client's requests so far.
struct Conn {
    socket: Vec<u8>,
    stream: Stream,
}

/// The X connections of this process, by socket (its inode).
static CONNS: Mutex<Option<HashMap<u64, Conn>>> = Mutex::new(None);

/// Whether this process has made an X connection: until it has, a write
/// is not looked at.
static ANY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// MIT-SHM's request number at each server (by socket), if it takes
/// descriptors (1.2); asked once.
static SHM: Mutex<Option<HashMap<Vec<u8>, Option<u8>>>> = Mutex::new(None);

fn inode(fd: i32) -> Option<u64> {
    // SAFETY: an all-zero `stat` is a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `st` is a valid out-parameter.
    (unsafe { libc::fstat(fd, &mut st) } == 0).then_some(st.st_ino)
}

/// Socket `fd` is now connected to the host display's socket `socket`.
pub fn connected(fd: i32, socket: &[u8]) {
    let Some(ino) = inode(fd) else { return };
    ANY.store(true, std::sync::atomic::Ordering::Relaxed);
    let mut c = CONNS.lock().unwrap_or_else(|e| e.into_inner());
    c.get_or_insert_with(HashMap::new)
        .insert(ino, Conn { socket: socket.to_vec(), stream: Stream::default() });
}

/// The `k`th byte of the host buffers `iov`.
fn byte_of(iov: &[libc::iovec], mut k: u64) -> u8 {
    for v in iov {
        if k < v.iov_len as u64 {
            // SAFETY: `k` is within this buffer, a checked host one.
            return unsafe { *(v.iov_base as *const u8).add(k as usize) };
        }
        k -= v.iov_len as u64;
    }
    0
}

/// The bytes `[from, from + n)` of `iov`.
fn bytes_of(iov: &[libc::iovec], from: u64, n: u64) -> Vec<u8> {
    (from..from + n).map(|k| byte_of(iov, k)).collect()
}

/// A write of host buffers `iov` (`total` bytes) to socket `fd`, if it is
/// an X connection: sent by `send` (the write the guest made, of the
/// buffers given it), a `ShmAttach` among them sent as `ShmAttachFd`.
/// `None` for any other socket.
pub fn write(
    fd: i32,
    iov: &[libc::iovec],
    mut send: impl FnMut(&[libc::iovec]) -> i64,
) -> Option<i64> {
    if !ANY.load(std::sync::atomic::Ordering::Relaxed) {
        return None;
    }
    let ino = inode(fd)?;
    let (socket, stream) = {
        let c = CONNS.lock().unwrap_or_else(|e| e.into_inner());
        let conn = c.as_ref()?.get(&ino)?;
        (conn.socket.clone(), conn.stream.clone())
    };
    let total: u64 = iov.iter().map(|v| v.iov_len as u64).sum();
    let byte = |k| byte_of(iov, k);
    let major = stream.auth.as_ref().and_then(|auth| shm_major(&socket, auth));
    let found = major.map_or(Found::None, |m| stream.find_attach(total, byte, m));
    let (upto, attach) = match found {
        Found::None => (total, None),
        Found::Whole(a) => (a, Some(a)),
        // Not yet whole: what is before it, the rest when it is.
        Found::Cut(a) if a > 0 => (a, None),
        Found::Cut(_) => (total, None),
    };
    let mut sent = 0;
    if upto > 0 {
        let part = crate::iovecs_part(iov, 0, upto);
        let r = send(&part);
        if r < 0 {
            return Some(r);
        }
        sent = r as u64;
    }
    if sent == upto
        && let Some(a) = attach
        && attach_fd(fd, major.unwrap_or(0), &bytes_of(iov, a, SHM_ATTACH_LEN), stream.big_endian)
    {
        sent += SHM_ATTACH_LEN;
    }
    let mut c = CONNS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(conn) = c.as_mut().and_then(|c| c.get_mut(&ino)) {
        conn.stream.advance(sent, byte);
    }
    Some(sent as i64)
}

/// Bytes of a send on socket `fd` (`iov`'s first `sent`) made elsewhere (a
/// message with control data, sent as it was): followed if it is an X
/// connection.
pub fn sent(fd: i32, iov: &[libc::iovec], sent: i64) {
    if sent <= 0 || !ANY.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    let Some(ino) = inode(fd) else { return };
    let mut c = CONNS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(conn) = c.as_mut().and_then(|c| c.get_mut(&ino)) {
        conn.stream.advance(sent as u64, |k| byte_of(iov, k));
    }
}

/// Send `ShmAttach` request `req` (16 bytes) on `fd` as `ShmAttachFd`
/// with the segment's file; whether it was (a segment fwe has no file of
/// is left to the server to refuse, as sent).
fn attach_fd(fd: i32, major: u8, req: &[u8], big_endian: bool) -> bool {
    let u32_at = |at: usize| {
        let v = [req[at], req[at + 1], req[at + 2], req[at + 3]];
        if big_endian { u32::from_be_bytes(v) } else { u32::from_le_bytes(v) }
    };
    let (seg, shmid, read_only) = (u32_at(4), u32_at(8) as i32, req[12]);
    let Some(record) = crate::sysvipc::current() else { return false };
    let Ok(path) = std::ffi::CString::new(crate::sysvipc::segment_path(&record, shmid)) else {
        return false;
    };
    let flags = if read_only != 0 { libc::O_RDONLY } else { libc::O_RDWR };
    // SAFETY: a NUL-terminated path of fwe's.
    let file = unsafe { libc::open(path.as_ptr(), flags | libc::O_CLOEXEC) };
    if file < 0 {
        return false;
    }
    let words: u16 = 3;
    let mut out = vec![major, SHM_ATTACH_FD];
    out.extend(if big_endian { words.to_be_bytes() } else { words.to_le_bytes() });
    out.extend(if big_endian { seg.to_be_bytes() } else { seg.to_le_bytes() });
    out.extend([read_only, 0, 0, 0]);
    let ok = send_with_fd(fd, &out, file);
    // SAFETY: our own descriptor, passed on (the server holds its copy).
    unsafe { libc::close(file) };
    ok
}

/// Send `data` on `fd` whole, descriptor `pass` with its first byte,
/// waiting for room as a blocking socket would.
fn send_with_fd(fd: i32, data: &[u8], pass: i32) -> bool {
    let mut at = 0;
    while at < data.len() {
        let mut iov =
            libc::iovec { iov_base: data[at..].as_ptr() as *mut _, iov_len: data.len() - at };
        // Room for one descriptor's control message, aligned for cmsghdr.
        let mut control = [0u64; 4];
        // SAFETY: an all-zero msghdr is valid; its fields are set below.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        if at == 0 {
            // SAFETY: CMSG_SPACE only computes a size.
            let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<i32>() as u32) };
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = space as _;
            // SAFETY: the control buffer holds one cmsghdr and an int.
            unsafe {
                let c = libc::CMSG_FIRSTHDR(&msg);
                (*c).cmsg_level = libc::SOL_SOCKET;
                (*c).cmsg_type = libc::SCM_RIGHTS;
                (*c).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<i32>() as u32) as _;
                std::ptr::write_unaligned(libc::CMSG_DATA(c).cast::<i32>(), pass);
            }
        }
        // SAFETY: a valid message over live buffers.
        let r = unsafe { libc::sendmsg(fd, &msg, 0) };
        if r > 0 {
            at += r as usize;
            continue;
        }
        let e = crate::host::last_errno();
        if r < 0 && (e == libc::EAGAIN || e == libc::EINTR) {
            let mut p = libc::pollfd { fd, events: libc::POLLOUT, revents: 0 };
            // SAFETY: one valid pollfd.
            unsafe { libc::poll(&mut p, 1, -1) };
            continue;
        }
        return at > 0;
    }
    true
}

/// MIT-SHM's request number at the server at `socket`, if it takes
/// descriptors, asked once with authorization `auth`.
fn shm_major(socket: &[u8], auth: &(Vec<u8>, Vec<u8>)) -> Option<u8> {
    let mut known = SHM.lock().unwrap_or_else(|e| e.into_inner());
    *known
        .get_or_insert_with(HashMap::new)
        .entry(socket.to_vec())
        .or_insert_with(|| query_shm(socket, auth))
}

/// Ask the server at `socket`, on a connection of fwe's with the client's
/// authorization, for MIT-SHM's request number, if its version is 1.2 or
/// later (it takes descriptors).
fn query_shm(socket: &[u8], auth: &(Vec<u8>, Vec<u8>)) -> Option<u8> {
    use std::io::{Read, Write};
    use std::os::unix::ffi::OsStrExt;
    let path = std::path::Path::new(std::ffi::OsStr::from_bytes(socket));
    let mut s = std::os::unix::net::UnixStream::connect(path).ok()?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(5))).ok()?;
    let (name, data) = auth;
    let mut setup = vec![b'l', 0, 11, 0, 0, 0];
    setup.extend((name.len() as u16).to_le_bytes());
    setup.extend((data.len() as u16).to_le_bytes());
    setup.extend([0, 0]);
    for part in [name, data] {
        setup.extend(part);
        setup.resize(pad4(setup.len()), 0);
    }
    // QueryExtension("MIT-SHM"), then (its number known from the reply)
    // ShmQueryVersion.
    let ext = b"MIT-SHM";
    let mut q = vec![98, 0];
    q.extend((2 + pad4(ext.len()) as u16 / 4).to_le_bytes());
    q.extend((ext.len() as u16).to_le_bytes());
    q.extend([0, 0]);
    q.extend(ext);
    q.resize(pad4(q.len()), 0);
    s.write_all(&setup).ok()?;
    s.write_all(&q).ok()?;
    let mut head = [0u8; 8];
    s.read_exact(&mut head).ok()?;
    if head[0] != 1 {
        return None;
    }
    let more = 4 * usize::from(u16::from_le_bytes([head[6], head[7]]));
    let mut rest = vec![0u8; more];
    s.read_exact(&mut rest).ok()?;
    let mut reply = [0u8; 32];
    s.read_exact(&mut reply).ok()?;
    if reply[0] != 1 || reply[8] == 0 {
        return None;
    }
    let major = reply[9];
    s.write_all(&[major, 0, 1, 0]).ok()?;
    s.read_exact(&mut reply).ok()?;
    if reply[0] != 1 {
        return None;
    }
    let (maj, min) =
        (u16::from_le_bytes([reply[8], reply[9]]), u16::from_le_bytes([reply[10], reply[11]]));
    (maj > 1 || (maj == 1 && min >= 2)).then_some(major)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup(name: &[u8], data: &[u8]) -> Vec<u8> {
        let mut s = vec![b'l', 0, 11, 0, 0, 0];
        s.extend((name.len() as u16).to_le_bytes());
        s.extend((data.len() as u16).to_le_bytes());
        s.extend([0, 0]);
        for part in [name, data] {
            s.extend(part);
            s.resize(pad4(s.len()), 0);
        }
        s
    }

    fn request(major: u8, minor: u8, body_words: u16) -> Vec<u8> {
        let mut r = vec![major, minor];
        r.extend((1 + body_words).to_le_bytes());
        r.extend(vec![0xaa; 4 * usize::from(body_words)]);
        r
    }

    fn attach(major: u8, seg: u32, shmid: u32) -> Vec<u8> {
        let mut r = vec![major, SHM_ATTACH, 4, 0];
        r.extend(seg.to_le_bytes());
        r.extend(shmid.to_le_bytes());
        r.extend([0, 0, 0, 0]);
        r
    }

    fn walked(s: &mut Stream, b: &[u8]) {
        s.advance(b.len() as u64, |k| b[k as usize]);
    }

    fn find(s: &Stream, b: &[u8]) -> Found {
        s.find_attach(b.len() as u64, |k| b[k as usize], 130)
    }

    #[test]
    fn displays_named_by_number_or_launchd_socket() {
        let d =
            |s: &str| parse(s.as_bytes()).map(|d| (d.number, String::from_utf8(d.socket).unwrap()));
        assert_eq!(d(":0"), Some((0, "/tmp/.X11-unix/X0".into())));
        assert_eq!(d("unix:99.0"), Some((99, "/tmp/.X11-unix/X99".into())));
        assert_eq!(
            d("/private/tmp/com.apple.launchd.ab12/org.xquartz:0"),
            Some((0, "/private/tmp/com.apple.launchd.ab12/org.xquartz".into()))
        );
        assert_eq!(d("localhost:10.0"), None);
        assert_eq!(d(":x"), None);
        assert_eq!(guest_display(b"/private/tmp/com.apple.launchd.ab12/org.xquartz:0"), b":0");
        assert_eq!(guest_display(b":99.1"), b":99.1");
    }

    #[test]
    fn the_setup_gives_its_authorization() {
        let mut s = Stream::default();
        walked(&mut s, &setup(b"MIT-MAGIC-COOKIE-1", &[7; 16]));
        assert_eq!(s.auth, Some((b"MIT-MAGIC-COOKIE-1".to_vec(), vec![7; 16])));
        let mut s = Stream::default();
        walked(&mut s, &setup(b"", b""));
        assert_eq!(s.auth, Some((vec![], vec![])));
    }

    #[test]
    fn an_attach_is_found_whole_after_other_requests() {
        let mut s = Stream::default();
        walked(&mut s, &setup(b"", b""));
        let mut b = request(1, 0, 7);
        let at = b.len() as u64;
        b.extend(attach(130, 5, 42));
        b.extend(request(130, 3, 2));
        assert_eq!(find(&s, &b), Found::Whole(at));
        // Another extension's minor 1, or an attach of another length: not it.
        let b2 = [request(131, 1, 3), request(130, 1, 2)].concat();
        assert_eq!(find(&s, &b2), Found::None);
    }

    #[test]
    fn requests_split_across_writes_keep_their_framing() {
        let mut s = Stream::default();
        walked(&mut s, &setup(b"", b""));
        let all = [request(55, 0, 300), attach(130, 1, 2)].concat();
        // Written in pieces cutting headers and bodies anywhere.
        let (a, rest) = all.split_at(3);
        walked(&mut s, a);
        let (b, rest) = rest.split_at(700);
        walked(&mut s, b);
        assert_eq!(find(&s, rest), Found::Whole((1204 - 703) as u64));
    }

    #[test]
    fn an_attach_cut_short_is_held_back() {
        let mut s = Stream::default();
        walked(&mut s, &setup(b"", b""));
        let b = [request(1, 0, 1), attach(130, 1, 2)[..10].to_vec()].concat();
        assert_eq!(find(&s, &b), Found::Cut(8));
        // A header cut before its minor, of MIT-SHM's number: held back too.
        let b = [request(1, 0, 1), vec![130]].concat();
        assert_eq!(find(&s, &b), Found::Cut(8));
        // One whose start went before is passed.
        let a = attach(130, 1, 2);
        walked(&mut s, &request(1, 0, 1));
        walked(&mut s, &a[..2]);
        assert_eq!(find(&s, &a[2..]), Found::None);
    }

    #[test]
    fn big_requests_are_framed_by_their_long_length() {
        let mut s = Stream::default();
        walked(&mut s, &setup(b"", b""));
        let mut big = vec![72, 2, 0, 0];
        big.extend(70000u32.to_le_bytes());
        big.resize(4 * 70000, 0x55);
        let b = [big, attach(130, 9, 9)].concat();
        assert_eq!(find(&s, &b), Found::Whole(280000));
    }
}
