//! A process's kernel state as bytes, for a `fork` child that is a fresh fwe
//! process rather than a host fork.
//!
//! A VM process cannot fork on the host (see `docs/hypervisor.md`), so its
//! fork child is started anew and handed the parent's memory and this state:
//! the kernel's own fields, the calling thread's signal state, and every
//! registry that describes the guest's descriptors and address space. The
//! descriptors themselves are inherited; only those the host does not pass
//! on, the kqueues behind `epoll` and `timerfd`, are rebuilt from the
//! records kept for them.
//!
//! The format is private to one fwe binary talking to itself: fields in a
//! fixed order, integers little-endian, byte strings length-prefixed.

use std::collections::{BTreeMap, HashMap, VecDeque};

/// Builds a snapshot.
#[derive(Default)]
pub struct Enc(Vec<u8>);

impl Enc {
    pub fn new() -> Enc {
        Enc::default()
    }
    pub fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    pub fn bool(&mut self, v: bool) {
        self.u8(v as u8);
    }
    pub fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub fn i32(&mut self, v: i32) {
        self.u32(v as u32);
    }
    pub fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    pub fn i64(&mut self, v: i64) {
        self.u64(v as u64);
    }
    pub fn bytes(&mut self, v: &[u8]) {
        self.u64(v.len() as u64);
        self.0.extend_from_slice(v);
    }
    pub fn map(&mut self, m: &BTreeMap<u64, u64>) {
        self.u64(m.len() as u64);
        for (&k, &v) in m {
            self.u64(k);
            self.u64(v);
        }
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// Reads a snapshot back. Reading past the end yields zeros and marks the
/// snapshot bad, checked once at the end with [`Dec::finish`].
pub struct Dec<'a> {
    buf: &'a [u8],
    at: usize,
    bad: bool,
}

impl<'a> Dec<'a> {
    pub fn new(buf: &'a [u8]) -> Dec<'a> {
        Dec { buf, at: 0, bad: false }
    }
    fn take(&mut self, n: usize) -> &'a [u8] {
        if self.bad || self.buf.len() - self.at < n {
            self.bad = true;
            return &[];
        }
        let s = &self.buf[self.at..self.at + n];
        self.at += n;
        s
    }
    fn array<const N: usize>(&mut self) -> [u8; N] {
        self.take(N).try_into().unwrap_or([0; N])
    }
    pub fn u8(&mut self) -> u8 {
        self.array::<1>()[0]
    }
    pub fn bool(&mut self) -> bool {
        self.u8() != 0
    }
    pub fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.array())
    }
    pub fn i32(&mut self) -> i32 {
        self.u32() as i32
    }
    pub fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.array())
    }
    pub fn i64(&mut self) -> i64 {
        self.u64() as i64
    }
    /// A count of items, each at least `min` bytes long: bounded by what is
    /// left, so a corrupt count cannot ask for a huge allocation.
    pub fn count(&mut self, min: usize) -> usize {
        let n = self.u64() as usize;
        if n > (self.buf.len() - self.at) / min.max(1) {
            self.bad = true;
            return 0;
        }
        n
    }
    pub fn bytes(&mut self) -> Vec<u8> {
        let n = self.count(1);
        self.take(n).to_vec()
    }
    pub fn map(&mut self) -> BTreeMap<u64, u64> {
        let n = self.count(16);
        (0..n).map(|_| (self.u64(), self.u64())).collect()
    }
    /// Whether everything has been read.
    pub fn at_end(&self) -> bool {
        self.bad || self.at == self.buf.len()
    }
    /// Whether everything read so far was there.
    pub fn whole(&self) -> bool {
        !self.bad
    }
    /// Whether everything read was there and nothing is left over.
    pub fn finish(&self) -> Result<(), String> {
        if self.bad || self.at != self.buf.len() {
            return Err("the fork state is malformed".into());
        }
        Ok(())
    }
}

/// Write a `fd -> record` map in a stable order.
pub(crate) fn fd_map<T>(e: &mut Enc, m: &HashMap<i32, T>, mut item: impl FnMut(&mut Enc, &T)) {
    let mut fds: Vec<&i32> = m.keys().collect();
    fds.sort();
    e.u64(fds.len() as u64);
    for fd in fds {
        e.i32(*fd);
        item(e, &m[fd]);
    }
}

/// Read a map written by [`fd_map`].
pub(crate) fn read_fd_map<T>(d: &mut Dec, mut item: impl FnMut(&mut Dec) -> T) -> HashMap<i32, T> {
    let n = d.count(4);
    (0..n)
        .map(|_| {
            let fd = d.i32();
            (fd, item(d))
        })
        .collect()
}

pub(crate) fn queue(e: &mut Enc, q: &VecDeque<[u8; crate::signalfd::SIGINFO_SIZE]>) {
    e.u64(q.len() as u64);
    for r in q {
        e.bytes(r);
    }
}

pub(crate) fn read_queue(d: &mut Dec) -> VecDeque<[u8; crate::signalfd::SIGINFO_SIZE]> {
    let n = d.count(8);
    (0..n).map(|_| d.bytes().try_into().unwrap_or([0; crate::signalfd::SIGINFO_SIZE])).collect()
}

/// Whether descriptor `fd` is close-on-exec.
#[cfg(not(target_os = "linux"))]
pub(crate) fn cloexec(fd: i32) -> bool {
    // SAFETY: F_GETFD only queries the descriptor.
    let f = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    f >= 0 && f & libc::FD_CLOEXEC != 0
}

/// Put a fresh kqueue at descriptor `fd`, which must be free: a fork child's
/// stand-in for a kqueue the host did not pass on.
#[cfg(not(target_os = "linux"))]
pub(crate) fn fresh_kqueue_at(fd: i32, cloexec: bool) -> bool {
    // SAFETY: plain host calls on descriptors this process owns.
    unsafe {
        // The kqueue's number is free in a child; anything open there is
        // not ours to replace (a stale record), so leave it.
        if libc::fcntl(fd, libc::F_GETFD) >= 0 {
            return false;
        }
        let kq = libc::kqueue();
        if kq < 0 {
            return false;
        }
        if kq != fd {
            if libc::dup2(kq, fd) < 0 {
                libc::close(kq);
                return false;
            }
            libc::close(kq);
        }
        if cloexec {
            libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut e = Enc::new();
        e.u8(7);
        e.bool(true);
        e.i32(-3);
        e.u64(u64::MAX);
        e.bytes(b"hello");
        e.map(&BTreeMap::from([(1, 2), (3, 4)]));
        let b = e.into_bytes();
        let mut d = Dec::new(&b);
        assert_eq!(d.u8(), 7);
        assert!(d.bool());
        assert_eq!(d.i32(), -3);
        assert_eq!(d.u64(), u64::MAX);
        assert_eq!(d.bytes(), b"hello");
        assert_eq!(d.map(), BTreeMap::from([(1, 2), (3, 4)]));
        assert!(d.finish().is_ok());
    }

    #[test]
    fn truncated_and_trailing_are_errors() {
        let mut e = Enc::new();
        e.bytes(b"abc");
        let b = e.into_bytes();
        let mut d = Dec::new(&b[..b.len() - 1]);
        let _ = d.bytes();
        assert!(d.finish().is_err());
        let d = Dec::new(&b);
        assert!(d.finish().is_err(), "unread bytes are an error");
        // A huge count does not allocate.
        let mut e = Enc::new();
        e.u64(u64::MAX);
        let b = e.into_bytes();
        let mut d = Dec::new(&b);
        assert!(d.bytes().is_empty());
        assert!(d.finish().is_err());
    }
}
