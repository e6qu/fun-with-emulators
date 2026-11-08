//! inotify: `inotify_init1`, `inotify_add_watch`, `inotify_rm_watch`, and
//! the events fwe raises as its processes act on files.
//!
//! The host's file events (`kqueue`, FSEvents) say neither which name a
//! directory gained nor that a file was opened, read or closed, so fwe
//! raises Linux's events itself, from the calls of every fwe process that
//! act on a watched file or on a file in a watched directory: what is
//! done by a program fwe does not run is not seen.
//!
//! The watches are a record every process sees ([`crate::shared::Record`]):
//! each names its instance, its watch descriptor, the file (host device
//! and inode), and its mask. An instance's descriptor is a host datagram
//! socket bound to a path in fwe's private directory, so a process that
//! raises an event sends it there, one datagram an event, and reading,
//! `poll` and `epoll` are the host's own. Beside it, three shared words
//! count the events queued (up to `fs.inotify.max_queued_events`, past
//! which events are dropped and the reader is given `IN_Q_OVERFLOW` once
//! it has read the rest), note an overflow, and keep the last event sent,
//! so an event identical to the one before it is merged with it, as Linux
//! merges them.

use crate::fdmarks::{self, Mark};
use crate::shared::{Data, Record};
use crate::snapshot::{Dec, Enc};
use crate::sysvipc::Proc;
use crate::{Kernel, Platform, uaccess};
use fwe_abi::inotify::*;
use fwe_abi::{err, errno, fcntl, nr};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

/// A watch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Watch {
    /// Its instance's socket path.
    pub inst: Vec<u8>,
    pub wd: i32,
    /// The file watched, as the host knows it.
    pub dev: u64,
    pub ino: u64,
    /// The events asked for, with `IN_ONESHOT` and `IN_EXCL_UNLINK`.
    pub mask: u32,
    /// Where the file was in the mount namespace's view (for
    /// `IN_UNMOUNT`).
    pub ns_path: Vec<u8>,
}

/// An instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instance {
    pub owner: Proc,
    /// Its socket's path.
    pub path: Vec<u8>,
    /// The user it is counted against (`max_user_instances`).
    pub uid: u32,
    pub next_wd: i32,
}

/// Every instance and watch.
#[derive(Clone, Debug, Default)]
pub struct Registry {
    pub instances: Vec<Instance>,
    pub watches: Vec<Watch>,
}

impl Data for Registry {
    fn encode(&self, e: &mut Enc) {
        e.u64(self.instances.len() as u64);
        for i in &self.instances {
            e.i32(i.owner.0);
            e.u64(i.owner.1);
            e.bytes(&i.path);
            e.u32(i.uid);
            e.i32(i.next_wd);
        }
        e.u64(self.watches.len() as u64);
        for w in &self.watches {
            e.bytes(&w.inst);
            e.i32(w.wd);
            e.u64(w.dev);
            e.u64(w.ino);
            e.u32(w.mask);
            e.bytes(&w.ns_path);
        }
    }

    fn decode(d: &mut Dec) -> Self {
        let n = d.count(28);
        let instances = (0..n)
            .map(|_| Instance {
                owner: (d.i32(), d.u64()),
                path: d.bytes(),
                uid: d.u32(),
                next_wd: d.i32(),
            })
            .collect();
        let n = d.count(40);
        let watches = (0..n)
            .map(|_| Watch {
                inst: d.bytes(),
                wd: d.i32(),
                dev: d.u64(),
                ino: d.u64(),
                mask: d.u32(),
                ns_path: d.bytes(),
            })
            .collect();
        Registry { instances, watches }
    }
}

impl Registry {
    /// Drop the instances (and their watches) of processes that have gone.
    fn reap(&mut self) -> bool {
        let gone: Vec<Vec<u8>> =
            self.instances.iter().filter(|i| !alive(i.owner)).map(|i| i.path.clone()).collect();
        for p in &gone {
            remove_files(p);
        }
        self.instances.retain(|i| !gone.contains(&i.path));
        let before = self.watches.len();
        self.watches.retain(|w| !gone.contains(&w.inst));
        !gone.is_empty() || self.watches.len() != before
    }

    /// Sysctl `fs.inotify.<name>`'s value.
    pub fn tunable(&self, name: &str) -> i64 {
        let default = match name {
            "max_queued_events" => MAX_QUEUED_EVENTS,
            "max_user_instances" => MAX_USER_INSTANCES,
            _ => MAX_USER_WATCHES,
        };
        crate::sysctl::number(format!("fs/inotify/{name}").as_bytes()).unwrap_or(default)
    }
}

fn alive(p: Proc) -> bool {
    p == crate::sysvipc::me() || crate::procreg::alive(p)
}

static REGISTRY: OnceLock<Record<Registry>> = OnceLock::new();
/// When this process last found no registry (monotonic milliseconds).
static MISSED: AtomicU64 = AtomicU64::new(0);

fn now_ms() -> u64 {
    static START: OnceLock<std::time::Instant> = OnceLock::new();
    START.get_or_init(std::time::Instant::now).elapsed().as_millis() as u64 + 1
}

fn registry_dir() -> Option<Vec<u8>> {
    let mut d = crate::fs::shm::user_dir().ok()?;
    d.extend_from_slice(format!("/v{}-inotify", crate::shared::FORMAT).as_bytes());
    Some(d)
}

/// The registry, every process's, if any process has made it (it lasts,
/// once made). A process that finds none looks again a second later at
/// the soonest, so a file call costs nothing while nothing is watched.
pub fn registry() -> Option<&'static Record<Registry>> {
    if let Some(r) = REGISTRY.get() {
        return Some(r);
    }
    let missed = MISSED.load(Ordering::Relaxed);
    let now = now_ms();
    if missed != 0 && now.saturating_sub(missed) < 1000 {
        return None;
    }
    match registry_dir().and_then(|d| Record::join(&d, 0).ok()) {
        Some(r) => {
            let _ = REGISTRY.set(r);
            REGISTRY.get()
        }
        None => {
            MISSED.store(now, Ordering::Relaxed);
            None
        }
    }
}

/// The registry, made if no process has made it yet.
fn make_registry() -> Option<&'static Record<Registry>> {
    if let Some(r) = registry() {
        return Some(r);
    }
    let r = Record::named("inotify", 0, Registry::default).ok()?;
    let _ = REGISTRY.set(r);
    REGISTRY.get()
}

/// Whether anything is watched: the generation of the registry last
/// looked at, and what it said.
static SEEN_GEN: AtomicU64 = AtomicU64::new(u64::MAX);
static SEEN_ANY: AtomicU32 = AtomicU32::new(0);

/// Whether any file is watched, by any process (cheap: a shared word is
/// read, the registry only when it changed).
pub fn watching() -> bool {
    let Some(r) = registry() else { return false };
    let g = r.generation();
    if g == SEEN_GEN.load(Ordering::Relaxed) {
        return SEEN_ANY.load(Ordering::Relaxed) != 0;
    }
    let any = !r.get().watches.is_empty();
    SEEN_ANY.store(u32::from(any), Ordering::Relaxed);
    SEEN_GEN.store(g, Ordering::Relaxed);
    any
}

/// This process's instances, by mark number: the socket path.
static INSTANCES: Mutex<Option<HashMap<u32, Vec<u8>>>> = Mutex::new(None);
static NEXT: AtomicU32 = AtomicU32::new(1);

fn instances<R>(f: impl FnOnce(&mut HashMap<u32, Vec<u8>>) -> R) -> R {
    let mut g = INSTANCES.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(HashMap::new))
}

/// The instance `fd` is a descriptor of: its socket's path.
pub fn instance_of(fd: i32) -> Option<Vec<u8>> {
    match fdmarks::any_marks().then(|| fdmarks::marked(fd)).flatten() {
        Some(Mark::Inotify(k)) => instances(|m| m.get(&k).cloned()),
        _ => None,
    }
}

/// The three shared words beside instance `path`: events queued, an
/// overflow, the last event sent (a hash).
fn queue_words(path: &[u8]) -> Option<&'static [AtomicU64; 3]> {
    static MAPS: Mutex<Option<HashMap<Vec<u8>, usize>>> = Mutex::new(None);
    let mut g = MAPS.lock().unwrap_or_else(|e| e.into_inner());
    let m = g.get_or_insert_with(HashMap::new);
    if let Some(&p) = m.get(path) {
        // SAFETY: a mapping made below, never unmapped.
        return Some(unsafe { &*(p as *const [AtomicU64; 3]) });
    }
    let c = std::ffi::CString::new([path, b".q"].concat()).ok()?;
    // SAFETY: a NUL-terminated path in fwe's private directory; the
    // mapping holds the file, the descriptor is closed again.
    let p = unsafe {
        let fd = libc::open(c.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
        if fd < 0 {
            return None;
        }
        let p = libc::mmap(
            std::ptr::null_mut(),
            24,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        );
        libc::close(fd);
        if p == libc::MAP_FAILED {
            return None;
        }
        p
    };
    m.insert(path.to_vec(), p as usize);
    // SAFETY: a shared mapping of 24 bytes, aligned, kept for good.
    Some(unsafe { &*(p as *const [AtomicU64; 3]) })
}

/// Remove instance `path`'s files.
fn remove_files(path: &[u8]) {
    for p in [path.to_vec(), [path, b".q"].concat()] {
        if let Ok(c) = std::ffi::CString::new(p) {
            // SAFETY: a NUL-terminated path in fwe's private directory.
            unsafe { libc::unlink(c.as_ptr()) };
        }
    }
}

/// `struct inotify_event` for `wd`, `mask`, `cookie` and `name`, its name
/// padded with NULs to a multiple of the header's size, as Linux pads it.
fn event(wd: i32, mask: u32, cookie: u32, name: &[u8]) -> Vec<u8> {
    let len = if name.is_empty() { 0 } else { (name.len() + 1).div_ceil(EVENT_SIZE) * EVENT_SIZE };
    let mut e = Vec::with_capacity(EVENT_SIZE + len);
    e.extend_from_slice(&wd.to_ne_bytes());
    e.extend_from_slice(&mask.to_ne_bytes());
    e.extend_from_slice(&cookie.to_ne_bytes());
    e.extend_from_slice(&(len as u32).to_ne_bytes());
    e.extend_from_slice(name);
    e.resize(EVENT_SIZE + len, 0);
    e
}

/// Queue an event on instance `inst`: merged with the one before it if
/// identical; past the queue's limit, dropped, the queue's last event
/// then saying so (`IN_Q_OVERFLOW`, once until it is read). Whether the
/// instance is still there (its socket gone: its process ended).
fn send(inst: &[u8], ev: &[u8], max: i64) -> bool {
    let Some(q) = queue_words(inst) else { return false };
    let h = crate::shared::hash(ev) | 1;
    if q[0].load(Ordering::SeqCst) > 0 && q[2].load(Ordering::SeqCst) == h {
        return true;
    }
    if q[0].fetch_add(1, Ordering::SeqCst) as i64 >= max {
        q[0].fetch_sub(1, Ordering::SeqCst);
        if q[1].swap(1, Ordering::SeqCst) == 0 {
            return datagram(inst, &event(-1, IN_Q_OVERFLOW, 0, b"")) != Gone;
        }
        return true;
    }
    q[2].store(h, Ordering::SeqCst);
    match datagram(inst, ev) {
        Sent::Yes => true,
        Sent::Gone => false,
        Sent::No => {
            q[0].fetch_sub(1, Ordering::SeqCst);
            if q[1].swap(1, Ordering::SeqCst) == 0 {
                let _ = datagram(inst, &event(-1, IN_Q_OVERFLOW, 0, b""));
            }
            true
        }
    }
}

/// What sending a datagram came to.
#[derive(PartialEq, Eq)]
enum Sent {
    Yes,
    /// Not sent: the queue is full.
    No,
    /// Nobody is there.
    Gone,
}
use Sent::Gone;

/// Send `ev` to instance `inst`'s socket.
fn datagram(inst: &[u8], ev: &[u8]) -> Sent {
    let r = sender(|s| {
        // SAFETY: a valid buffer and address of the lengths given.
        crate::net::at_unix_path(inst, |a, l| unsafe {
            libc::sendto(s, ev.as_ptr().cast(), ev.len(), libc::MSG_DONTWAIT, a, l) as i32
        })
    });
    match r {
        Ok(n) if n == ev.len() as i32 => Sent::Yes,
        _ => match crate::host::last_errno() {
            libc::ENOENT | libc::ECONNREFUSED => Sent::Gone,
            _ => Sent::No,
        },
    }
}

/// Instance `inst` has gone without being closed (its process ended):
/// its watches and its files go too.
fn forget(inst: &[u8]) {
    let Some(r) = registry() else { return };
    let _ = r.update_maybe(|t| {
        let before = (t.instances.len(), t.watches.len());
        t.instances.retain(|i| i.path != inst);
        t.watches.retain(|w| w.inst != inst);
        Ok(((), before != (t.instances.len(), t.watches.len())))
    });
    remove_files(inst);
}

/// Run `f` with this process's socket for sending events.
fn sender(f: impl FnOnce(i32) -> Result<i32, i32>) -> Result<i32, i32> {
    static S: Mutex<(i32, i32)> = Mutex::new((-1, 0));
    let mut g = S.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: getpid cannot fail.
    let me = unsafe { libc::getpid() };
    if g.0 < 0 || g.1 != me {
        // SAFETY: plain host call; the socket is fwe's own.
        let s = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0) };
        let s = crate::fdtable::reserve(s).map_err(|_| errno::EMFILE)?;
        *g = (s, me);
    }
    f(g.0)
}

/// What an event is about: a file, as the host knows it, and its place.
#[derive(Clone, Debug, Default)]
pub struct Subject {
    pub dev: u64,
    pub ino: u64,
    pub dir: bool,
    pub nlink: u64,
    /// The directory it is in, and its name there.
    pub parent: Option<(u64, u64)>,
    pub name: Vec<u8>,
}

/// The events a watched directory hears of its children.
const CHILD_EVENTS: u32 = IN_ACCESS
    | IN_MODIFY
    | IN_ATTRIB
    | IN_CLOSE_WRITE
    | IN_CLOSE_NOWRITE
    | IN_OPEN
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_CREATE
    | IN_DELETE;

#[allow(clippy::unnecessary_cast)] // `libc::stat` field types differ by host
fn identity(st: &libc::stat) -> (u64, u64, bool, u64) {
    (
        st.st_dev as u64,
        st.st_ino as u64,
        st.st_mode & libc::S_IFMT == libc::S_IFDIR,
        st.st_nlink as u64,
    )
}

/// The device an overlay's files are on to their watches: its own, so a
/// watch through the overlay is not of a layer's file seen another way.
fn overlay_dev(l: &crate::overlay::Layers) -> u64 {
    (1 << 63) | (crate::shared::hash(l.paths().next().unwrap_or_default()) >> 1)
}

/// What a file of an overlay is to its watches: the lower file it was
/// copied up from, or itself, on the overlay's device; a copy-up does not
/// change it, as Linux's overlay keeps a file's inode.
fn overlay_ident(fd: i32, dev: u64) -> Option<(u64, u64)> {
    let ino = crate::overlay::origin_of(fd).map(|(_, i)| i).or_else(|| {
        // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a valid out-parameter.
        (unsafe { libc::fstat(fd, &mut st) } == 0).then(|| identity(&st).1)
    })?;
    Some((dev, ino))
}

/// `s`, `name` in host directory `dir`, as seen through overlay `l`.
fn through_overlay(mut s: Subject, dir: i32, name: &[u8], l: &crate::overlay::Layers) -> Subject {
    use std::os::fd::{AsRawFd, FromRawFd};
    let dev = overlay_dev(l);
    let file = std::ffi::CString::new(name).ok().and_then(|c| {
        // SAFETY: a live directory and a NUL-terminated name; the
        // descriptor is owned below.
        let fd = unsafe {
            libc::openat(
                dir,
                c.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        // SAFETY: a fresh descriptor this owns.
        (fd >= 0).then(|| unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
    });
    match file.and_then(|f| overlay_ident(f.as_raw_fd(), dev)) {
        Some((d, i)) => (s.dev, s.ino) = (d, i),
        None => s.dev = dev,
    }
    if s.parent.is_some()
        && let Some(p) = overlay_ident(dir, dev)
    {
        s.parent = Some(p);
    }
    s
}

/// The subject `name` in directory `dir` (a host descriptor) is, not
/// following a final link.
pub fn subject_at(dir: i32, name: &[u8]) -> Option<Subject> {
    // SAFETY: zeroed bytes are a valid `stat`.
    let mut ds: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: valid out-parameters, a live descriptor and a NUL-terminated
    // name.
    let ok = unsafe {
        libc::fstat(dir, &mut ds) == 0
            && libc::fstatat(dir, c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) == 0
    };
    if !ok {
        return None;
    }
    let (dev, ino, isdir, nlink) = identity(&st);
    let (pdev, pino, _, _) = identity(&ds);
    let own = name == b".";
    Some(Subject {
        dev,
        ino,
        dir: isdir,
        nlink,
        parent: (!own).then_some((pdev, pino)),
        name: if own { Vec::new() } else { name.to_vec() },
    })
}

/// The subject what `r` resolved is (as an overlay shows it, in one).
fn resolved_subject(r: &crate::fs::Resolved) -> Option<Subject> {
    let dir = std::os::fd::AsRawFd::as_raw_fd(&r.dir);
    let s = subject_at(dir, &r.name)?;
    Some(match &r.ovl {
        Some(o) => through_overlay(s, dir, &r.name, &o.layers),
        None => s,
    })
}

/// The subject a descriptor's file is, and where it is (its host path's
/// directory and name), as an overlay shows it if it was opened in one.
pub fn subject_of_fd(fd: i32) -> Option<Subject> {
    let mut s = host_subject_of_fd(fd)?;
    if let Some(l) = fdmarks::origin(fd).and_then(|o| o.ovl) {
        let dev = overlay_dev(&l);
        if let Some(id) = overlay_ident(fd, dev) {
            (s.dev, s.ino) = id;
        }
        let parent = crate::fs::host_path_of(fd).and_then(|p| {
            let i = p.iter().rposition(|&b| b == b'/')?;
            let c = std::ffi::CString::new(&p[..i.max(1)]).ok()?;
            // SAFETY: a NUL-terminated path; the descriptor is closed below.
            let d = unsafe {
                libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC)
            };
            if d < 0 {
                return None;
            }
            let id = overlay_ident(d, dev);
            // SAFETY: the descriptor opened above.
            unsafe { libc::close(d) };
            id
        });
        if s.parent.is_some() {
            s.parent = parent;
        }
    }
    Some(s)
}

/// [`subject_of_fd`] as the host has it.
fn host_subject_of_fd(fd: i32) -> Option<Subject> {
    // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out-parameter.
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return None;
    }
    let (dev, ino, isdir, nlink) = identity(&st);
    let mut s = Subject { dev, ino, dir: isdir, nlink, parent: None, name: Vec::new() };
    if let Some(path) = crate::fs::host_path_of(fd) {
        let slash = path.iter().rposition(|&b| b == b'/');
        if let Some(i) = slash.filter(|&i| i + 1 < path.len()) {
            let parent = if i == 0 { b"/".to_vec() } else { path[..i].to_vec() };
            if let Ok(c) = std::ffi::CString::new(parent) {
                // SAFETY: zeroed bytes are a valid `stat`.
                let mut ds: libc::stat = unsafe { std::mem::zeroed() };
                // SAFETY: a NUL-terminated path and a valid out-parameter.
                if unsafe { libc::stat(c.as_ptr(), &mut ds) } == 0 {
                    let (pdev, pino, _, _) = identity(&ds);
                    s.parent = Some((pdev, pino));
                    s.name = path[i + 1..].to_vec();
                }
            }
        }
    }
    Some(s)
}

/// Raise `mask` about `s` (with `cookie` for a move): to the watches of
/// its directory, with its name, and of the file itself. A one-shot watch
/// that fires goes, with `IN_IGNORED`.
pub fn raise(s: &Subject, mask: u32, cookie: u32) {
    let Some(r) = registry() else { return };
    let reg = r.get();
    if reg.watches.is_empty() {
        return;
    }
    let max = reg.tunable("max_queued_events");
    // A directory's events say so, but what it hears of itself moving.
    let isdir = if s.dir && mask & IN_MOVE_SELF == 0 { IN_ISDIR } else { 0 };
    let mut spent: Vec<(Vec<u8>, i32)> = Vec::new();
    let mut gone: Vec<Vec<u8>> = Vec::new();
    if let Some((pdev, pino)) = s.parent
        && mask & CHILD_EVENTS != 0
    {
        for w in reg.watches.iter().filter(|w| w.dev == pdev && w.ino == pino) {
            // `IN_EXCL_UNLINK` passes over what is done through an open
            // file that has been unlinked.
            const THROUGH_FILE: u32 =
                IN_ACCESS | IN_MODIFY | IN_OPEN | IN_CLOSE_WRITE | IN_CLOSE_NOWRITE;
            let unlinked = s.nlink == 0 && !s.dir && mask & THROUGH_FILE != 0;
            if w.mask & mask == 0 || (w.mask & IN_EXCL_UNLINK != 0 && unlinked) {
                continue;
            }
            if !send(&w.inst, &event(w.wd, mask | isdir, cookie, &s.name), max) {
                gone.push(w.inst.clone());
                continue;
            }
            if w.mask & IN_ONESHOT != 0 {
                spent.push((w.inst.clone(), w.wd));
            }
        }
    }
    // What only a directory hears of an entry, not the file itself.
    const ENTRY_ONLY: u32 = IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO;
    for w in reg.watches.iter().filter(|w| w.dev == s.dev && w.ino == s.ino) {
        if mask & ENTRY_ONLY != 0 || w.mask & mask == 0 || spent.contains(&(w.inst.clone(), w.wd)) {
            continue;
        }
        if !send(&w.inst, &event(w.wd, mask | isdir, cookie, b""), max) {
            gone.push(w.inst.clone());
            continue;
        }
        if w.mask & IN_ONESHOT != 0 {
            spent.push((w.inst.clone(), w.wd));
        }
    }
    for g in &gone {
        forget(g);
    }
    if !spent.is_empty() {
        drop_watches(|w| spent.contains(&(w.inst.clone(), w.wd)), 0);
    }
}

/// Remove the watches `which` picks, each instance hearing `IN_IGNORED`
/// (after `before`, if not 0: `IN_UNMOUNT`).
fn drop_watches(which: impl Fn(&Watch) -> bool, before: u32) {
    let Some(r) = registry() else { return };
    let gone = r.update_maybe(|t| {
        let gone: Vec<Watch> = t.watches.iter().filter(|w| which(w)).cloned().collect();
        t.watches.retain(|w| !which(w));
        let changed = !gone.is_empty();
        Ok((gone, changed))
    });
    let Ok(gone) = gone else { return };
    let max = r.get().tunable("max_queued_events");
    for w in gone {
        if before != 0 {
            send(&w.inst, &event(w.wd, before, 0, b""), max);
        }
        send(&w.inst, &event(w.wd, IN_IGNORED, 0, b""), max);
    }
}

/// File `s` is gone (its last link removed): its watches hear
/// `IN_DELETE_SELF` and go.
pub fn deleted(s: &Subject) {
    let Some(r) = registry() else { return };
    let max = r.get().tunable("max_queued_events");
    for w in r.get().watches.iter().filter(|w| w.dev == s.dev && w.ino == s.ino) {
        if w.mask & IN_DELETE_SELF != 0 {
            send(&w.inst, &event(w.wd, IN_DELETE_SELF, 0, b""), max);
        }
    }
    drop_watches(|w| w.dev == s.dev && w.ino == s.ino, 0);
}

/// The mount at namespace path `point` is gone: the watches of what was
/// in it hear `IN_UNMOUNT` and go.
pub fn unmounted(point: &[u8]) {
    if !watching() {
        return;
    }
    drop_watches(|w| crate::mounts::under(&w.ns_path, point).is_some(), IN_UNMOUNT);
}

/// A cookie tying a move's two events together.
pub fn cookie() -> u32 {
    static N: AtomicU32 = AtomicU32::new(0);
    // SAFETY: getpid cannot fail.
    let pid = unsafe { libc::getpid() } as u32;
    (pid << 12) ^ N.fetch_add(1, Ordering::Relaxed).wrapping_add(1)
}

/// A read of instance descriptor `fd` into the guest's `buf` of `len`
/// bytes: whole events, as many as fit (`EINVAL` if the first does not),
/// waiting for one unless the descriptor is non-blocking. `None` for
/// another descriptor.
pub fn try_read(fd: i32, buf: u64, len: u64) -> Option<i64> {
    read_events(fd, buf, len, true)
}

/// [`try_read`], waiting for an event only if `wait` (and the
/// descriptor blocks).
fn read_events(fd: i32, buf: u64, len: u64, wait: bool) -> Option<i64> {
    let path = instance_of(fd)?;
    let q = queue_words(&path)?;
    // SAFETY: plain host call.
    let nonblock = !wait || unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_NONBLOCK != 0;
    let mut out: Vec<u8> = Vec::new();
    loop {
        match crate::netlink::next_len(fd) {
            Some(n) => {
                if out.len() + n > len as usize {
                    if out.is_empty() {
                        return Some(err(errno::EINVAL));
                    }
                    break;
                }
                let mut ev = vec![0u8; n];
                // SAFETY: a buffer of `n` bytes; the socket is the guest's.
                let got = unsafe { libc::recv(fd, ev.as_mut_ptr().cast(), n, libc::MSG_DONTWAIT) };
                if got <= 0 {
                    continue;
                }
                let mask = u32::from_ne_bytes(ev[4..8].try_into().unwrap());
                if mask == IN_Q_OVERFLOW {
                    // The overflow, counted apart: one may come again.
                    q[1].store(0, Ordering::SeqCst);
                } else if q[0].fetch_sub(1, Ordering::SeqCst) == 1 {
                    q[2].store(0, Ordering::SeqCst);
                }
                out.extend_from_slice(&ev[..got as usize]);
            }
            None if !out.is_empty() => break,
            None if nonblock => return Some(err(errno::EAGAIN)),
            None => {
                if crate::thread::deliverable() != 0 {
                    return Some(err(errno::EINTR));
                }
                let mut p = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
                // SAFETY: one valid pollfd.
                unsafe { libc::poll(&mut p, 1, 20) };
            }
        }
    }
    match uaccess::write_from(buf, &out) {
        Ok(()) => Some(out.len() as i64),
        Err(e) => Some(err(e)),
    }
}

/// A read or write of an instance's descriptor other than `read`: a
/// write refused (`EINVAL`), as Linux has none; a positioned one too
/// (`ESPIPE`); `readv` filling each buffer with whole events in turn.
/// `None` for another descriptor or call.
pub fn io(nr: u64, a: &[u64; 6]) -> Option<i64> {
    use fwe_abi::nr as n;
    if !matches!(
        nr,
        n::WRITE
            | n::WRITEV
            | n::PWRITE64
            | n::PWRITEV
            | n::PWRITEV2
            | n::READV
            | n::PREAD64
            | n::PREADV
            | n::PREADV2
    ) {
        return None;
    }
    let fd = a[0] as i32;
    instance_of(fd)?;
    Some(match nr {
        n::WRITE | n::WRITEV => err(errno::EINVAL),
        n::READV => {
            let iov = match uaccess::read_bytes(a[1], (a[2] as usize).min(1024) * 16) {
                Ok(b) => b,
                Err(e) => return Some(err(e)),
            };
            let mut total = 0i64;
            for (i, c) in iov.chunks_exact(16).enumerate() {
                let base = u64::from_ne_bytes(c[0..8].try_into().unwrap());
                let len = u64::from_ne_bytes(c[8..16].try_into().unwrap());
                if len == 0 {
                    continue;
                }
                match read_events(fd, base, len, i == 0 || total == 0) {
                    Some(r) if r > 0 => total += r,
                    Some(r) if total == 0 => return Some(r),
                    _ => break,
                }
            }
            total
        }
        _ => err(errno::ESPIPE),
    })
}

/// A socket call on an instance's descriptor, which is no socket to the
/// guest: `ENOTSOCK`.
pub fn refused(nr: u64, a: &[u64; 6]) -> Option<i64> {
    use fwe_abi::nr as n;
    let socket = matches!(
        nr,
        n::RECVFROM
            | n::RECVMSG
            | n::RECVMMSG
            | n::SENDTO
            | n::SENDMSG
            | n::SENDMMSG
            | n::GETSOCKOPT
            | n::SETSOCKOPT
            | n::GETSOCKNAME
            | n::GETPEERNAME
            | n::SHUTDOWN
            | n::BIND
            | n::CONNECT
            | n::LISTEN
            | n::ACCEPT
            | n::ACCEPT4
    );
    (socket && fdmarks::any_marks() && instance_of(a[0] as i32).is_some())
        .then(|| err(errno::ENOTSOCK))
}

/// The process is ending: each open file not open elsewhere in it is
/// closed (its close raised), and its instances go.
pub fn exiting() {
    if watching() {
        for fd in crate::fdtable::open_fds() {
            close_event(fd);
        }
    }
    drop_own(|_| true);
}

/// The process is about to replace its program by a host `execve`, which
/// closes its close-on-exec descriptors: their closes raised, and the
/// instances among them gone.
pub fn exec_closing() {
    let mut cloexec = Vec::new();
    for fd in crate::fdtable::open_fds() {
        // SAFETY: plain host call on an open descriptor.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags >= 0 && flags & libc::FD_CLOEXEC != 0 {
            if watching() {
                close_event(fd);
            }
            if let Some(p) = instance_of(fd) {
                cloexec.push(p);
            }
        }
    }
    if !cloexec.is_empty() {
        drop_own(|p| cloexec.iter().any(|c| c == p));
    }
}

/// Raise the close of descriptor `fd`, if it is a file's and the process
/// has no other descriptor of it.
fn close_event(fd: i32) {
    if instance_of(fd).is_some() || fdmarks::shared_elsewhere(fd) {
        return;
    }
    let Some(s) = subject_of_fd(fd) else { return };
    // SAFETY: plain host call.
    let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    raise(
        &s,
        if fl & libc::O_ACCMODE != libc::O_RDONLY { IN_CLOSE_WRITE } else { IN_CLOSE_NOWRITE },
        0,
    );
}

/// Remove this process's instances whose paths `which` picks, with their
/// watches and files.
fn drop_own(which: impl Fn(&[u8]) -> bool) {
    let Some(r) = registry() else { return };
    let me = crate::sysvipc::me();
    // Most processes have none: no need to take the lock.
    if !r.get().instances.iter().any(|i| i.owner == me && which(&i.path)) {
        return;
    }
    let gone = r.update_maybe(|t| {
        let gone: Vec<Vec<u8>> = t
            .instances
            .iter()
            .filter(|i| i.owner == me && which(&i.path))
            .map(|i| i.path.clone())
            .collect();
        t.instances.retain(|i| !gone.contains(&i.path));
        t.watches.retain(|w| !gone.contains(&w.inst));
        let changed = !gone.is_empty();
        Ok((gone, changed))
    });
    for p in gone.unwrap_or_default() {
        remove_files(&p);
    }
}

/// `fd` is closed: an instance it was the last descriptor of goes, with
/// its watches, in the process that made it.
pub fn closed(fd: i32) {
    let Some(Mark::Inotify(k)) = fdmarks::any_marks().then(|| fdmarks::marked(fd)).flatten() else {
        return;
    };
    if fdmarks::shared_elsewhere(fd) {
        return;
    }
    let Some(path) = instances(|m| m.remove(&k)) else { return };
    let me = crate::sysvipc::me();
    if let Some(r) = registry() {
        let _ = r.update_maybe(|t| {
            let mine = t.instances.iter().any(|i| i.path == path && i.owner == me);
            if mine {
                t.instances.retain(|i| i.path != path);
                t.watches.retain(|w| w.inst != path);
                remove_files(&path);
            }
            Ok(((), mine))
        });
    }
}

/// `/proc/<pid>/fdinfo/<fd>`'s lines for an instance's descriptor: one a
/// watch.
pub fn fdinfo(fd: i32) -> Option<String> {
    let path = instance_of(fd)?;
    let reg = registry()?.get();
    let mut out = String::new();
    for w in reg.watches.iter().filter(|w| w.inst == path) {
        out.push_str(&format!(
            "inotify wd:{} ino:{:x} sdev:{:x} mask:{:x} ignored_mask:0 fhandle-bytes:8 fhandle-type:1 f_handle:{:016x}\n",
            w.wd, w.ino, w.dev, w.mask, w.ino
        ));
    }
    Some(out)
}

/// Write the process's instances into a fork snapshot or exec state.
pub(crate) fn save(e: &mut Enc) {
    e.u32(NEXT.load(Ordering::Relaxed));
    instances(|m| {
        e.u64(m.len() as u64);
        for (&k, p) in m.iter() {
            e.u32(k);
            e.bytes(p);
        }
    });
}

/// What [`save`] wrote, in the new process.
pub(crate) fn load(d: &mut Dec) {
    NEXT.store(d.u32(), Ordering::Relaxed);
    let n = d.count(12);
    for _ in 0..n {
        let (k, p) = (d.u32(), d.bytes());
        instances(|m| m.insert(k, p));
    }
}

/// What a file call is to raise once it has run, worked out before it
/// does (what it removes, renames or closes is gone after).
pub enum Plan {
    /// A close of a descriptor of `s`, open to write or not.
    Close(Subject, bool),
    /// An open that may create or truncate: whether the file was there.
    Open { existed: bool, truncates: bool },
    /// An unlink of `s`.
    Unlink(Subject),
    /// A rename of `s`, from directory `from` to directory `to` (and
    /// name), over `over` if something was there.
    Rename { s: Subject, to: Option<(u64, u64)>, to_name: Vec<u8>, over: Option<Subject> },
}

impl<P: Platform> Kernel<P> {
    /// The subject `path` from `dirfd` names (`follow`ing a final link).
    fn subject_path(&self, dirfd: i32, path: &[u8], follow: bool) -> Option<Subject> {
        let r = self.fs().resolve(dirfd, path, follow).ok()?;
        resolved_subject(&r)
    }

    /// Before file call `nr`: what [`after`](Self::inotify_after) needs.
    pub(crate) fn inotify_before(&self, n: u64, a: &[u64; 6]) -> Option<Plan> {
        if !watching() {
            return None;
        }
        let path = |at: u64| uaccess::read_cstr(at, uaccess::PATH_MAX).ok();
        match n {
            nr::CLOSE => {
                let fd = a[0] as i32;
                if instance_of(fd).is_some() || fdmarks::shared_elsewhere(fd) {
                    return None;
                }
                let s = subject_of_fd(fd)?;
                // SAFETY: plain host call.
                let fl = unsafe { libc::fcntl(fd, libc::F_GETFL) };
                Some(Plan::Close(s, fl & libc::O_ACCMODE != libc::O_RDONLY))
            }
            nr::OPENAT | nr::OPENAT2 => {
                let flags = if n == nr::OPENAT { a[2] } else { uaccess::read::<u64>(a[2]).ok()? };
                if flags & (fcntl::O_CREAT | fcntl::O_TRUNC) == 0 {
                    return None;
                }
                let p = path(a[1])?;
                let existed = self.subject_path(a[0] as i32, &p, true).is_some();
                Some(Plan::Open { existed, truncates: flags & fcntl::O_TRUNC != 0 })
            }
            nr::UNLINKAT => {
                let p = path(a[1])?;
                Some(Plan::Unlink(self.subject_path(a[0] as i32, &p, false)?))
            }
            nr::RENAMEAT | nr::RENAMEAT2 => {
                let (from, to) = (path(a[1])?, path(a[3])?);
                let s = self.subject_path(a[0] as i32, &from, false)?;
                let r = self.fs().resolve(a[2] as i32, &to, false).ok()?;
                let dir = std::os::fd::AsRawFd::as_raw_fd(&r.dir);
                // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
                let mut ds: libc::stat = unsafe { std::mem::zeroed() };
                // SAFETY: a live descriptor and a valid out-parameter.
                let to_dir = (unsafe { libc::fstat(dir, &mut ds) } == 0).then(|| {
                    let (d, i, _, _) = identity(&ds);
                    (d, i)
                });
                Some(Plan::Rename {
                    s,
                    to: to_dir,
                    to_name: r.name.clone(),
                    over: subject_at(dir, &r.name),
                })
            }
            _ => None,
        }
    }

    /// After file call `nr` (with `a`) returned `r`: raise its events.
    pub(crate) fn inotify_after(&self, n: u64, a: &[u64; 6], r: i64, plan: Option<Plan>) {
        if r < 0 || !watching() {
            return;
        }
        let path = |at: u64| uaccess::read_cstr(at, uaccess::PATH_MAX).ok();
        match (n, plan) {
            (nr::CLOSE, Some(Plan::Close(s, wrote))) => {
                raise(&s, if wrote { IN_CLOSE_WRITE } else { IN_CLOSE_NOWRITE }, 0);
            }
            (nr::OPENAT | nr::OPENAT2, plan) => {
                let Some(s) = subject_of_fd(r as i32) else { return };
                if let Some(Plan::Open { existed: false, .. }) = plan {
                    raise(&s, IN_CREATE, 0);
                }
                raise(&s, IN_OPEN, 0);
                // A file that was there, truncated as it opens.
                if let Some(Plan::Open { existed: true, truncates: true }) = plan {
                    raise(&s, IN_MODIFY, 0);
                }
            }
            (nr::MKDIRAT | nr::MKNODAT, _) => {
                if let Some(s) = path(a[1]).and_then(|p| self.subject_path(a[0] as i32, &p, false))
                {
                    raise(&s, IN_CREATE, 0);
                }
            }
            (nr::SYMLINKAT, _) => {
                if let Some(s) = path(a[2]).and_then(|p| self.subject_path(a[1] as i32, &p, false))
                {
                    raise(&s, IN_CREATE, 0);
                }
            }
            (nr::LINKAT, _) => {
                if let Some(s) = path(a[3]).and_then(|p| self.subject_path(a[2] as i32, &p, false))
                {
                    raise(&Subject { parent: None, ..s.clone() }, IN_ATTRIB, 0);
                    raise(&s, IN_CREATE, 0);
                }
            }
            (nr::UNLINKAT, Some(Plan::Unlink(s))) => {
                let left = Subject { nlink: s.nlink.saturating_sub(1), ..s.clone() };
                if s.dir || s.nlink <= 1 {
                    // A file's link count changes (to 0); then it is gone.
                    if !s.dir {
                        raise(&Subject { parent: None, nlink: 0, ..s.clone() }, IN_ATTRIB, 0);
                    }
                    raise(&Subject { nlink: 0, ..s.clone() }, IN_DELETE, 0);
                    deleted(&s);
                } else {
                    raise(&Subject { parent: None, ..left.clone() }, IN_ATTRIB, 0);
                    raise(&left, IN_DELETE, 0);
                }
            }
            (nr::RENAMEAT | nr::RENAMEAT2, Some(Plan::Rename { s, to, to_name, over })) => {
                // Two names of one file: nothing moved.
                if over.as_ref().is_some_and(|o| (o.dev, o.ino) == (s.dev, s.ino)) {
                    return;
                }
                const RENAME_EXCHANGE: u64 = 2;
                let exchange = n == nr::RENAMEAT2 && a[4] & RENAME_EXCHANGE != 0;
                let moves = |s: &Subject, to: Option<(u64, u64)>, to_name: Vec<u8>| {
                    let c = cookie();
                    raise(s, IN_MOVED_FROM, c);
                    raise(&Subject { parent: to, name: to_name, ..s.clone() }, IN_MOVED_TO, c);
                    raise(&Subject { parent: None, ..s.clone() }, IN_MOVE_SELF, 0);
                };
                moves(&s, to, to_name);
                match over {
                    // Each where the other was.
                    Some(o) if exchange => moves(&o, s.parent, s.name.clone()),
                    // What was there is gone, its last link with it.
                    Some(o) if o.dir || o.nlink <= 1 => {
                        if !o.dir {
                            raise(&Subject { parent: None, nlink: 0, ..o.clone() }, IN_ATTRIB, 0);
                        }
                        deleted(&o);
                    }
                    Some(o) => {
                        raise(&Subject { parent: None, nlink: o.nlink - 1, ..o }, IN_ATTRIB, 0)
                    }
                    None => {}
                }
            }
            (nr::FCHOWNAT, _) if a[2] as u32 == u32::MAX && a[3] as u32 == u32::MAX => {}
            (nr::FCHMODAT | nr::FCHMODAT2 | nr::FCHOWNAT, _) => {
                let follow = n == nr::FCHMODAT
                    || a[if n == nr::FCHOWNAT { 4 } else { 3 }] & fcntl::AT_SYMLINK_NOFOLLOW == 0;
                let p = path(a[1]).unwrap_or_default();
                let s = if p.is_empty() {
                    subject_of_fd(a[0] as i32)
                } else {
                    self.subject_path(a[0] as i32, &p, follow)
                };
                if let Some(s) = s {
                    raise(&s, IN_ATTRIB, 0);
                }
            }
            (nr::UTIMENSAT, _) => {
                let p = if a[1] == 0 { None } else { path(a[1]) };
                let s = match p {
                    Some(p) if !p.is_empty() => {
                        self.subject_path(a[0] as i32, &p, a[3] & fcntl::AT_SYMLINK_NOFOLLOW == 0)
                    }
                    _ => subject_of_fd(a[0] as i32),
                };
                // Both times set is an attribute change; one alone, an
                // access or a modification, as Linux reports them.
                const UTIME_OMIT: i64 = (1 << 30) - 2;
                let (atime, mtime) = if a[2] == 0 {
                    (true, true)
                } else {
                    match uaccess::read::<[i64; 4]>(a[2]) {
                        Ok(t) => (t[1] != UTIME_OMIT, t[3] != UTIME_OMIT),
                        Err(_) => return,
                    }
                };
                let mask = match (atime, mtime) {
                    (true, true) => IN_ATTRIB,
                    (true, false) => IN_ACCESS,
                    (false, true) => IN_MODIFY,
                    (false, false) => return,
                };
                if let Some(s) = s {
                    raise(&s, mask, 0);
                }
            }
            (nr::SETXATTR | nr::REMOVEXATTR | nr::LSETXATTR | nr::LREMOVEXATTR, _) => {
                let follow = matches!(n, nr::SETXATTR | nr::REMOVEXATTR);
                if let Some(s) =
                    path(a[0]).and_then(|p| self.subject_path(fcntl::AT_FDCWD as i32, &p, follow))
                {
                    raise(&s, IN_ATTRIB, 0);
                }
            }
            (nr::FCHOWN, _) if a[1] as u32 == u32::MAX && a[2] as u32 == u32::MAX => {}
            (nr::FCHMOD | nr::FCHOWN | nr::FSETXATTR | nr::FREMOVEXATTR, _) => {
                if let Some(s) = subject_of_fd(a[0] as i32) {
                    raise(&s, IN_ATTRIB, 0);
                }
            }
            (nr::TRUNCATE, _) => {
                if let Some(s) =
                    path(a[0]).and_then(|p| self.subject_path(fcntl::AT_FDCWD as i32, &p, true))
                {
                    raise(&s, IN_MODIFY, 0);
                }
            }
            _ => {}
        }
    }

    /// `inotify_init1(flags)`.
    pub(crate) fn sys_inotify_init1(&mut self, flags: u64) -> i64 {
        if flags & !(IN_NONBLOCK | IN_CLOEXEC) != 0 {
            return err(errno::EINVAL);
        }
        let Some(r) = make_registry() else { return err(errno::ENOMEM) };
        let uid = self.creds.uid;
        let me = crate::sysvipc::me();
        static N: AtomicU32 = AtomicU32::new(0);
        let mut path = match crate::fs::shm::user_dir() {
            Ok(d) => d,
            Err(e) => return err(e),
        };
        path.extend_from_slice(
            format!(
                "/v{}-in-{}-{}",
                crate::shared::FORMAT,
                me.0,
                N.fetch_add(1, Ordering::Relaxed)
            )
            .as_bytes(),
        );
        let made = r.update_maybe(|t| {
            let reaped = t.reap();
            let max = t.tunable("max_user_instances");
            if t.instances.iter().filter(|i| i.uid == uid).count() as i64 >= max {
                return Err(errno::EMFILE);
            }
            t.instances.push(Instance { owner: me, path: path.clone(), uid, next_wd: 1 });
            let _ = reaped;
            Ok(((), true))
        });
        if let Err(e) = made {
            return err(e);
        }
        let fail = |e: i32| {
            let _ = r.update(|t| {
                t.instances.retain(|i| i.path != path);
                Ok(())
            });
            remove_files(&path);
            err(e)
        };
        // The queue's words, then the socket.
        let Ok(q) = std::ffi::CString::new([&path[..], b".q"].concat()) else {
            return fail(errno::EINVAL);
        };
        // SAFETY: a NUL-terminated path in fwe's private directory.
        let qfd = unsafe {
            libc::open(
                q.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC,
                0o600,
            )
        };
        // SAFETY: the descriptor just opened.
        if qfd < 0 || unsafe { libc::ftruncate(qfd, 24) } != 0 {
            return fail(errno::ENOMEM);
        }
        // SAFETY: the descriptor opened above.
        unsafe { libc::close(qfd) };
        // SAFETY: plain host call; the socket is the guest's descriptor.
        let s = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0) };
        if s < 0 {
            return fail(errno::EMFILE);
        }
        // SAFETY: a valid address of the length given.
        if crate::net::at_unix_path(&path, |a, l| unsafe { libc::bind(s, a, l) }) != Ok(0) {
            // SAFETY: the socket made above.
            unsafe { libc::close(s) };
            return fail(errno::ENOMEM);
        }
        // Room for the queue's events.
        let room: libc::c_int = 8 << 20;
        // SAFETY: a valid option value; plain host calls on the new socket.
        unsafe {
            libc::setsockopt(
                s,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&room as *const libc::c_int).cast(),
                4,
            );
            if flags & IN_NONBLOCK != 0 {
                libc::fcntl(s, libc::F_SETFL, libc::O_NONBLOCK);
            }
            if flags & IN_CLOEXEC != 0 {
                libc::fcntl(s, libc::F_SETFD, libc::FD_CLOEXEC);
            }
        }
        let k = NEXT.fetch_add(1, Ordering::Relaxed);
        instances(|m| m.insert(k, path.clone()));
        fdmarks::mark(s, Mark::Inotify(k));
        s as i64
    }

    /// `inotify_add_watch(fd, path, mask)`: the watch descriptor.
    pub(crate) fn sys_inotify_add_watch(&mut self, fd: u64, path: u64, mask: u64) -> i64 {
        let mask = mask as u32;
        if mask & IN_MASK_ADD != 0 && mask & IN_MASK_CREATE != 0 {
            return err(errno::EINVAL);
        }
        if mask & IN_ALL_EVENTS == 0 {
            return err(errno::EINVAL);
        }
        let fd = fd as i32;
        // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a valid out-parameter.
        if fd < 0 || unsafe { libc::fstat(fd, &mut st) } != 0 {
            return err(errno::EBADF);
        }
        let Some(inst) = instance_of(fd) else { return err(errno::EINVAL) };
        let name = match uaccess::read_cstr(path, uaccess::PATH_MAX) {
            Ok(n) => n,
            Err(e) => return err(e),
        };
        let follow = mask & IN_DONT_FOLLOW == 0;
        let resolved = match self.fs().resolve(fcntl::AT_FDCWD as i32, &name, follow) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        let Some(s) = resolved_subject(&resolved) else {
            return err(errno::ENOENT);
        };
        if mask & IN_ONLYDIR != 0 && !s.dir {
            return err(errno::ENOTDIR);
        }
        // Read permission on it, by the effective ids.
        let nofollow = if follow { 0 } else { fcntl::AT_SYMLINK_NOFOLLOW };
        let r = self.sys_faccessat(fcntl::AT_FDCWD as u64, path, 4, fcntl::AT_EACCESS | nofollow);
        if r < 0 {
            return r;
        }
        let ns_path = resolved.ns_path.clone().unwrap_or_default();
        let kept = mask & (IN_ALL_EVENTS | IN_ONESHOT | IN_EXCL_UNLINK);
        let uid = self.creds.uid;
        let Some(r) = registry() else { return err(errno::ENOMEM) };
        let wd = r.update(|t| {
            if let Some(w) =
                t.watches.iter_mut().find(|w| w.inst == inst && w.dev == s.dev && w.ino == s.ino)
            {
                if mask & IN_MASK_CREATE != 0 {
                    return Err(errno::EEXIST);
                }
                w.mask = if mask & IN_MASK_ADD != 0 { w.mask | kept } else { kept };
                return Ok(w.wd);
            }
            let users: Vec<&Vec<u8>> =
                t.instances.iter().filter(|i| i.uid == uid).map(|i| &i.path).collect();
            let count = t.watches.iter().filter(|w| users.contains(&&w.inst)).count();
            if count as i64 >= t.tunable("max_user_watches") {
                return Err(errno::ENOSPC);
            }
            let i = t.instances.iter_mut().find(|i| i.path == inst).ok_or(errno::EINVAL)?;
            let wd = i.next_wd;
            i.next_wd += 1;
            t.watches.push(Watch {
                inst: inst.clone(),
                wd,
                dev: s.dev,
                ino: s.ino,
                mask: kept,
                ns_path,
            });
            Ok(wd)
        });
        match wd {
            Ok(wd) => wd as i64,
            Err(e) => err(e),
        }
    }

    /// `inotify_rm_watch(fd, wd)`.
    pub(crate) fn sys_inotify_rm_watch(&mut self, fd: u64, wd: u64) -> i64 {
        let fd = fd as i32;
        // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a valid out-parameter.
        if fd < 0 || unsafe { libc::fstat(fd, &mut st) } != 0 {
            return err(errno::EBADF);
        }
        let Some(inst) = instance_of(fd) else { return err(errno::EINVAL) };
        let wd = wd as i32;
        let known = registry()
            .is_some_and(|r| r.get().watches.iter().any(|w| w.inst == inst && w.wd == wd));
        if !known {
            return err(errno::EINVAL);
        }
        drop_watches(|w| w.inst == inst && w.wd == wd, 0);
        0
    }
}

/// An event's data that reads or writes descriptor `fd` (`IN_ACCESS`,
/// `IN_MODIFY`), after file call `nr` returned `r`.
pub fn after_io(nr: u64, a: &[u64; 6], r: i64) {
    use fwe_abi::nr as n;
    let io = matches!(
        nr,
        n::READ
            | n::READV
            | n::PREAD64
            | n::PREADV
            | n::PREADV2
            | n::WRITE
            | n::WRITEV
            | n::PWRITE64
            | n::PWRITEV
            | n::PWRITEV2
            | n::FTRUNCATE
            | n::FALLOCATE
            | n::SENDFILE
            | n::SPLICE
            | n::COPY_FILE_RANGE
            | n::GETDENTS64
    );
    let any = matches!(nr, n::FTRUNCATE | n::FALLOCATE | n::GETDENTS64);
    if !io || r < 0 || (r == 0 && !any) || !watching() {
        return;
    }
    let (fd, mask) = match nr {
        n::GETDENTS64 => (a[0], IN_ACCESS),
        n::READ | n::READV | n::PREAD64 | n::PREADV | n::PREADV2 => (a[0], IN_ACCESS),
        n::WRITE
        | n::WRITEV
        | n::PWRITE64
        | n::PWRITEV
        | n::PWRITEV2
        | n::FTRUNCATE
        | n::FALLOCATE => (a[0], IN_MODIFY),
        n::SENDFILE => {
            raise_fd(a[1] as i32, IN_ACCESS);
            (a[0], IN_MODIFY)
        }
        n::SPLICE | n::COPY_FILE_RANGE => {
            raise_fd(a[0] as i32, IN_ACCESS);
            (a[2], IN_MODIFY)
        }
        _ => return,
    };
    raise_fd(fd as i32, mask);
}

fn raise_fd(fd: i32, mask: u32) {
    if instance_of(fd).is_some() {
        return;
    }
    if let Some(s) = subject_of_fd(fd) {
        raise(&s, mask, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_are_laid_out_and_padded_as_linux_has_them() {
        let e = event(3, IN_CREATE, 7, b"abc");
        assert_eq!(e.len(), EVENT_SIZE + 16);
        assert_eq!(i32::from_ne_bytes(e[0..4].try_into().unwrap()), 3);
        assert_eq!(u32::from_ne_bytes(e[12..16].try_into().unwrap()), 16);
        assert_eq!(&e[16..20], b"abc\0");
        assert_eq!(event(1, IN_IGNORED, 0, b"").len(), EVENT_SIZE);
        // A name of 16 bytes takes 32, its NUL included.
        assert_eq!(event(1, IN_OPEN, 0, &[b'a'; 16]).len(), EVENT_SIZE + 32);
    }

    #[test]
    fn the_registry_round_trips() {
        let mut r = Registry::default();
        r.instances.push(Instance { owner: (1, 2), path: b"/p".to_vec(), uid: 0, next_wd: 3 });
        r.watches.push(Watch {
            inst: b"/p".to_vec(),
            wd: 2,
            dev: 4,
            ino: 5,
            mask: IN_OPEN,
            ns_path: b"/x".to_vec(),
        });
        let mut e = Enc::new();
        r.encode(&mut e);
        let b = e.into_bytes();
        let mut d = Dec::new(&b);
        let back = Registry::decode(&mut d);
        assert!(d.finish().is_ok());
        assert_eq!(back.instances, r.instances);
        assert_eq!(back.watches, r.watches);
        assert_eq!(back.tunable("max_queued_events"), MAX_QUEUED_EVENTS);
    }
}
