//! State that every fwe process sees: a record in memory every fwe process
//! maps ([`crate::procstore::named`]), as a kernel keeps state every
//! process sees in its own memory. Mount tables, namespaces, System V IPC
//! and the cgroup tree are such records.
//!
//! A record is named by a path in fwe's private directory on the host (its
//! [`Record::dir`]), which is made only for host objects that belong with
//! it ([`host_dir`]: an abstract socket's node, say); its data, its lock
//! and the generation count each change counts are in the shared memory.
//! Each process keeps a copy of the data, and reads it again only when
//! another has changed it. A type that keeps its changes
//! ([`Data::changes`]) has each appended to a journal beside the data,
//! which a process applies to its copy, until the journal outgrows the
//! data and the data is written whole again; others are written whole each
//! time. A record of thousands of objects (System V IPC's) so costs a
//! change what the change holds, not what the record does.

use crate::host::errno_to_linux;
use crate::procstore::named::{self, Slot};
use crate::snapshot::{Dec, Enc};
use fwe_abi::errno;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// What a record holds.
pub trait Data: Clone + Default + Send + Sync + 'static {
    fn encode(&self, e: &mut Enc);
    fn decode(d: &mut Dec) -> Self;
    /// Whether decoded data is whole (a record read while being made is
    /// not).
    fn valid(&self) -> bool {
        true
    }
    /// The changes made since the data was read or last asked, encoded
    /// for [`Data::apply`] and forgotten: `false` for a type that does not
    /// keep them, which is written whole each time.
    fn changes(&mut self, _e: &mut Enc) -> bool {
        false
    }
    /// Forget the changes made since the data was read or last asked
    /// (they are what it is, not changes of it).
    fn forget_changes(&mut self) {
        self.changes(&mut Enc::new());
    }
    /// Apply changes [`Data::changes`] encoded (keeping none of them as
    /// changes of its own).
    fn apply(&mut self, _d: &mut Dec) {}
}

/// The size a journal may reach before the data is written whole, when
/// the data is smaller.
const JOURNAL_MIN: usize = 64 << 10;

#[cfg(target_os = "macos")]
const UL_COMPARE_AND_WAIT_SHARED: u32 = 3;
#[cfg(target_os = "macos")]
const ULF_NO_ERRNO: u32 = 0x0100_0000;
#[cfg(target_os = "macos")]
const ULF_WAKE_ALL: u32 = 0x0000_0100;

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn __ulock_wait2(
        op: u32,
        addr: *mut libc::c_void,
        value: u64,
        timeout_ns: u64,
        value2: u64,
    ) -> libc::c_int;
    fn __ulock_wake(op: u32, addr: *mut libc::c_void, wake_value: u64) -> libc::c_int;
}

/// Sleep up to `slice` while shared word `word` reads `seen` (its low half,
/// which every change changes), a shared host address wait any process's
/// change ends ([`wake_all`]).
fn wait_word(word: &AtomicU64, seen: u64, slice: std::time::Duration) {
    #[cfg(target_os = "macos")]
    // SAFETY: a shared word of the store's; the host sleeps while its low
    // half still reads `seen`'s.
    unsafe {
        __ulock_wait2(
            UL_COMPARE_AND_WAIT_SHARED | ULF_NO_ERRNO,
            word.as_ptr().cast(),
            seen & 0xffff_ffff,
            slice.as_nanos().max(1) as u64,
            0,
        );
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (word, seen);
        std::thread::sleep(slice.min(std::time::Duration::from_millis(1)));
    }
}

/// Wake every process waiting for the word to change.
fn wake_all(word: &AtomicU64) {
    #[cfg(target_os = "macos")]
    // SAFETY: wakes waiters on the address; reads nothing.
    unsafe {
        __ulock_wake(
            UL_COMPARE_AND_WAIT_SHARED | ULF_NO_ERRNO | ULF_WAKE_ALL,
            word.as_ptr().cast(),
            0,
        );
    }
    #[cfg(not(target_os = "macos"))]
    let _ = word;
}

/// Sleep up to `slice` while shared word `word` reads `seen`.
pub(crate) fn wait_word_for(word: &AtomicU64, seen: u64, slice: std::time::Duration) {
    if word.load(Ordering::Acquire) == seen {
        wait_word(word, seen, slice);
    }
}

/// Wake every process waiting for shared word `word` to change.
pub(crate) fn wake_word(word: &AtomicU64) {
    wake_all(word);
}

/// FNV-1a: stable across processes and fwe builds.
pub fn hash(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325u64, |h, &b| (h ^ b as u64).wrapping_mul(0x100000001b3))
}

/// The layout of records and what they hold: part of every record's
/// name, so a record written by another fwe build is never read as this
/// one's. Raised whenever a record's encoding or a namespace's initial
/// contents change.
pub const FORMAT: u32 = 46;

/// A number no other call of any process gives: for the names of host
/// objects of fwe's (a System V segment's memory, an eventfd's counter).
pub fn unique() -> u64 {
    static N: AtomicU64 = AtomicU64::new(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let pid = crate::host::pid() as u64;
    hash(&[now.to_le_bytes(), pid.to_le_bytes(), n.to_le_bytes()].concat())
}

/// A name no other record has: the kind, this process and a count.
fn fresh_name(kind: &str) -> String {
    static N: AtomicU64 = AtomicU64::new(0);
    let pid = crate::host::pid();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("{kind}-{pid}-{now}-{}", N.fetch_add(1, Ordering::Relaxed))
}

/// Take the exclusive `flock` of `fd`, one of fwe's own locks, as Linux
/// takes a lock of its kernel's: the thread is not asleep while it waits
/// (it gives up the processor between tries), so `/proc` shows it running,
/// never sleeping in a wait the guest did not ask for, which a program
/// that waits for another to sleep (in `pause`, say) would take for that.
/// A wait past a second blocks. Async-signal-safe.
pub fn lock_exclusive(fd: i32) {
    let now = || {
        let mut t = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: a valid out-parameter.
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) };
        t.tv_sec * 1_000_000_000 + t.tv_nsec
    };
    // (The caller's `errno`, as a signal handler that calls this needs.)
    let saved = crate::host::last_errno();
    let start = now();
    // SAFETY: plain host calls on the caller's descriptor.
    unsafe {
        while libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) != 0 {
            match crate::host::last_errno() {
                libc::EWOULDBLOCK if now() - start <= 1_000_000_000 => libc::sched_yield(),
                // A signal came: the lock is still to take.
                libc::EINTR => 0,
                _ => {
                    while libc::flock(fd, libc::LOCK_EX) != 0
                        && crate::host::last_errno() == libc::EINTR
                    {}
                    break;
                }
            };
        }
    }
    crate::host::set_errno(saved);
}

/// The host directory of the record named `dir`, made if it is not there:
/// for host objects that belong with the record (the nodes of a network
/// namespace's abstract sockets, say), which go with it.
pub fn host_dir(dir: &[u8]) -> Result<(), i32> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(std::ffi::OsStr::from_bytes(dir))
        .map_err(|e| e.raw_os_error().map_or(errno::EIO, errno_to_linux))
}

/// The identity of the record named `dir`, if there is one.
pub fn id_of(dir: &[u8]) -> Option<u64> {
    named::find(dir).map(|s| s.id())
}

/// The note kept beside the record named `dir`'s data, if it has one.
pub fn note(dir: &[u8]) -> Option<Vec<u8>> {
    named::find(dir)?.note()
}

/// Keep `bytes` as the note beside the record named `dir`'s data.
pub fn set_note(dir: &[u8], bytes: &[u8]) -> Result<(), i32> {
    let slot = named::find(dir).ok_or(errno::ENOENT)?;
    let held = slot.lock();
    slot.set_note(&held, bytes);
    Ok(())
}

/// A process's copy of a record's data: the generation it is at, and
/// where in the journal (its epoch and offset) the changes after it begin.
struct Copy<T> {
    at: u64,
    data: Arc<T>,
    journal: Option<(u32, u32)>,
}

/// One record, as this process sees it.
pub struct Record<T: Data> {
    /// The record's name.
    dir: Vec<u8>,
    /// Its identity (a namespace's number in `/proc/self/ns`).
    id: u64,
    slot: Slot,
    /// The data as last read (none while a change is being made, or before
    /// it is first read).
    cache: Mutex<Option<Copy<T>>>,
}

impl<T: Data> std::fmt::Debug for Record<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Record({})", String::from_utf8_lossy(&self.dir))
    }
}

impl<T: Data> Record<T> {
    /// The record called `name`, made with `initial` if it does not exist.
    /// `id` is its identity, or 0 for the one it was given.
    pub fn named(name: &str, id: u64, initial: impl FnOnce() -> T) -> Result<Record<T>, i32> {
        let mut dir = crate::fs::shm::user_dir()?;
        dir.extend_from_slice(format!("/v{FORMAT}-{name}").as_bytes());
        Record::open_or_make(dir, id, initial)
    }

    /// The record named `dir`, inside another record's (whose life it
    /// shares), made with `initial` if it does not exist.
    pub fn at(dir: Vec<u8>, initial: impl FnOnce() -> T) -> Result<Record<T>, i32> {
        Record::open_or_make(dir, 0, initial)
    }

    /// A new record of `kind` holding `data` (after collecting those no
    /// process holds any more, see [`collect`]).
    pub fn fresh(kind: &str, data: T) -> Result<Record<T>, i32> {
        collect();
        Record::named(&fresh_name(kind), 0, || data)
    }

    /// The record named `dir` ([`Record::dir`]), which must exist and hold
    /// data of this kind (one a parent process had). It is never written
    /// here.
    pub fn join(dir: &[u8], id: u64) -> Result<Record<T>, i32> {
        let slot = named::find(dir).ok_or(errno::ENOENT)?;
        if !slot.has_data() {
            return Err(errno::ENOENT);
        }
        let r = Record::with(dir.to_vec(), id, slot);
        let copy = r.read_current(None).map_err(|_| errno::ENOENT)?;
        *r.cache.lock().unwrap_or_else(|e| e.into_inner()) = Some(copy);
        Ok(r)
    }

    fn with(dir: Vec<u8>, id: u64, slot: Slot) -> Record<T> {
        let id = if id != 0 { id } else { slot.id() };
        Record { dir, id, slot, cache: Mutex::new(None) }
    }

    fn open_or_make(dir: Vec<u8>, id: u64, initial: impl FnOnce() -> T) -> Result<Record<T>, i32> {
        let r = Record::with(dir.clone(), id, named::find_or_make(&dir));
        r.with_lock(|held| {
            if r.slot.has_data() {
                let copy = r.read_current(None)?;
                *r.cache.lock().unwrap_or_else(|e| e.into_inner()) = Some(copy);
            } else {
                let at = r.generation() + 1;
                let mut t = initial();
                // (What it holds now is not a change of it.)
                t.forget_changes();
                let mut enc = Enc::new();
                t.encode(&mut enc);
                let epoch = r.slot.write_whole(held, at, &enc.into_bytes());
                r.slot.advance(held, at);
                *r.cache.lock().unwrap_or_else(|e| e.into_inner()) =
                    Some(Copy { at, data: Arc::new(t), journal: Some((epoch, 0)) });
            }
            Ok(())
        })?;
        Ok(r)
    }

    /// The record's name: a path in fwe's private directory ([`host_dir`]).
    pub fn dir(&self) -> &[u8] {
        &self.dir
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    /// The changes in `journal` (bytes from offset `start` of the journal)
    /// after generation `after` and up to `upto`, in order, one for each
    /// generation, and the offset past the last of them. A change written
    /// again for the same generation (its writer ended before the change
    /// counted) stands for the one before it.
    fn changes_in(journal: &[u8], start: u32, after: u64, upto: u64) -> (Vec<(u64, Vec<u8>)>, u32) {
        let mut d = Dec::new(journal);
        let mut out: Vec<(u64, Vec<u8>)> = Vec::new();
        let mut end = start;
        while !d.at_end() {
            let (at, body) = (d.u64(), d.bytes());
            if !d.whole() || at > upto {
                // (Changes past `upto` are read the next time.)
                break;
            }
            end = start + d.position() as u32;
            out.retain(|&(g, _)| g < at);
            if at > after {
                out.push((at, body));
            }
        }
        (out, end)
    }

    /// The data as it is now: `copy` (if any) brought up to date from the
    /// journal when it holds every change since, else read whole. What a
    /// change made meanwhile tore is read again.
    fn read_current(&self, copy: Option<&Copy<T>>) -> Result<Copy<T>, i32> {
        let mut last = Err(errno::EIO);
        for _ in 0..100 {
            let from = copy.and_then(|c| c.journal);
            let Some(read) = self.slot.read(from) else {
                std::thread::yield_now();
                continue;
            };
            let (base_at, base) = match read.data {
                Some((at, bytes)) => {
                    let mut d = Dec::new(&bytes);
                    let t = T::decode(&mut d);
                    if d.finish().is_err() || !t.valid() {
                        last = Err(errno::EIO);
                        std::thread::yield_now();
                        continue;
                    }
                    (at, Arc::new(t))
                }
                // (Read whole when there is no copy.)
                None => match copy {
                    Some(c) => (c.at, c.data.clone()),
                    None => {
                        std::thread::yield_now();
                        continue;
                    }
                },
            };
            let (changes, end) =
                Self::changes_in(&read.journal, read.start, base_at, read.generation);
            let mut at = base_at;
            let mut data = base;
            if !changes.is_empty() {
                let mut t = Arc::try_unwrap(data).unwrap_or_else(|a| (*a).clone());
                let mut torn = false;
                for (g, body) in changes {
                    if g != at + 1 {
                        torn = true;
                        break;
                    }
                    let mut d = Dec::new(&body);
                    t.apply(&mut d);
                    if d.finish().is_err() {
                        torn = true;
                        break;
                    }
                    at = g;
                }
                if torn {
                    last = Err(errno::EIO);
                    std::thread::yield_now();
                    continue;
                }
                data = Arc::new(t);
            }
            if at == read.generation {
                return Ok(Copy { at, data, journal: Some((read.epoch, end)) });
            }
            last = Err(errno::EIO);
            std::thread::yield_now();
        }
        last
    }

    /// Under the lock: the data as it is now, the cached copy taken when
    /// it is current (no other process changed it since), else read.
    fn take_locked(&self) -> Result<(T, Option<(u32, u32)>), i32> {
        let now = self.generation();
        let held = self.cache.lock().unwrap_or_else(|e| e.into_inner()).take();
        let copy = match held {
            Some(c) if c.at == now => c,
            held => self.read_current(held.as_ref())?,
        };
        Ok((Arc::try_unwrap(copy.data).unwrap_or_else(|a| (*a).clone()), copy.journal))
    }

    /// Under the lock: `t` is the data now, for every process. A type
    /// that keeps its changes has them appended to the journal; the data
    /// is written whole once the journal outgrows it.
    fn put_locked(&self, held: &named::Held, mut t: T) {
        let at = self.generation() + 1;
        let mut entry = Enc::with_capacity(256);
        entry.u64(at);
        let kept = entry.section(|e| t.changes(e));
        let entry = entry.into_bytes();
        let (whole, journal) = self.slot.sizes();
        let journal = if kept && whole > 0 && journal + entry.len() <= whole.max(JOURNAL_MIN) {
            self.slot.append(held, &entry)
        } else {
            let mut enc = Enc::new();
            t.encode(&mut enc);
            (self.slot.write_whole(held, at, &enc.into_bytes()), 0)
        };
        self.slot.advance(held, at);
        *self.cache.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(Copy { at, data: Arc::new(t), journal: Some(journal) });
    }

    /// Under the lock: `t`, which `f` left as it was, is the cached copy
    /// again.
    fn restore_locked(&self, mut t: T, journal: Option<(u32, u32)>) {
        t.forget_changes();
        *self.cache.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(Copy { at: self.generation(), data: Arc::new(t), journal });
    }

    /// Run `f` holding the record's lock.
    fn with_lock<R>(&self, f: impl FnOnce(&named::Held) -> Result<R, i32>) -> Result<R, i32> {
        // Waiting for another process's lock: fwe's work, not a wait of
        // the guest's.
        let _busy = crate::procstore::Busy::new();
        let held = self.slot.lock();
        f(&held)
    }

    /// The record's generation: it changes with every change of its data.
    pub fn generation(&self) -> u64 {
        self.slot.generation()
    }

    /// Wait until the data changes from generation `seen`, `until` passes
    /// (`EAGAIN`) or a signal comes for the guest (`EINTR`), in slices as
    /// a futex wait does.
    pub fn wait_change(&self, seen: u64, until: Option<std::time::Instant>) -> Result<(), i32> {
        loop {
            if self.generation() != seen {
                return Ok(());
            }
            if crate::thread::deliverable() != 0 {
                return Err(errno::EINTR);
            }
            let now = std::time::Instant::now();
            let slice = match until {
                Some(d) if now >= d => return Err(errno::EAGAIN),
                Some(d) => (d - now).min(crate::futex::SIGNAL_CHECK),
                None => crate::futex::SIGNAL_CHECK,
            };
            self.slot.wait(seen, slice.as_nanos().max(1) as u64);
        }
    }

    /// The data as it is now.
    pub fn get(&self) -> Arc<T> {
        let now = self.generation();
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(c) = &*cache
            && c.at == now
        {
            return c.data.clone();
        }
        match self.read_current(cache.as_ref()) {
            Ok(fresh) => {
                let data = fresh.data.clone();
                *cache = Some(fresh);
                data
            }
            // Torn by changes each time it was read: the copy as it was.
            Err(_) => cache.as_ref().map_or_else(|| Arc::new(T::default()), |c| c.data.clone()),
        }
    }

    /// Change the data with `f`, for every process.
    pub fn update<R>(&self, f: impl FnOnce(&mut T) -> Result<R, i32>) -> Result<R, i32> {
        self.with_lock(|held| {
            let (mut t, _) = self.take_locked()?;
            let r = f(&mut t)?;
            self.put_locked(held, t);
            Ok(r)
        })
    }

    /// Change the data with `f`, for every process, if `f` says it changed
    /// it: the generation moves only then (a waiter that looked again and
    /// must go on waiting changes nothing, so does not wake itself).
    pub fn update_maybe<R>(
        &self,
        f: impl FnOnce(&mut T) -> Result<(R, bool), i32>,
    ) -> Result<R, i32> {
        self.with_lock(|held| {
            let (mut t, journal) = self.take_locked()?;
            let (r, changed) = f(&mut t)?;
            if changed {
                self.put_locked(held, t);
            } else {
                self.restore_locked(t, journal);
            }
            Ok(r)
        })
    }

    /// Write the record's identity into a fork snapshot or exec state.
    pub fn save(&self, e: &mut Enc) {
        e.bytes(&self.dir);
        e.u64(self.id);
    }

    /// The record [`Record::save`] wrote, joined.
    pub fn load(d: &mut Dec) -> Result<Record<T>, i32> {
        let (dir, id) = (d.bytes(), d.u64());
        Record::join(&dir, id)
    }
}

/// An optional shared record, as a namespace that may be the initial one
/// (`None`) is kept, written into a snapshot or exec state.
pub fn save_opt<T: Data>(e: &mut Enc, r: &Option<Arc<Record<T>>>) {
    match r {
        Some(r) => {
            e.bool(true);
            r.save(e);
        }
        None => e.bool(false),
    }
}

/// What [`save_opt`] wrote.
pub fn load_opt<T: Data>(d: &mut Dec) -> Result<Option<Arc<Record<T>>>, i32> {
    if !d.bool() {
        return Ok(None);
    }
    Record::load(d).map(|r| Some(Arc::new(r)))
}

/// How long a record is spared after it was made: one made for a `clone`
/// is held by no process until the child's record names it.
const YOUNG: std::time::Duration = std::time::Duration::from_secs(60);

/// Remove the records no live process holds, as a kernel frees a namespace
/// when its last process leaves: namespaces nobody is in, tmpfs directories
/// and rootfs `/dev/shm` directories no live mount table shows, records
/// another fwe build wrote, the initial mount table of a rootfs that is
/// gone, the tracing mailboxes of processes that are gone, and the owners
/// kept for socket nodes that are gone.
///
/// It runs at most once a minute ([`YOUNG`], within which nothing would be
/// removed anyway), as a fresh fwe starts, in a process of its own: a
/// marker's time says when.
pub fn collect() {
    use std::os::unix::ffi::OsStrExt;
    let Ok(base) = crate::fs::shm::user_dir() else { return };
    let marker = [&base[..], format!("/v{FORMAT}-collected").as_bytes()].concat();
    let marker = std::ffi::OsStr::from_bytes(&marker);
    let recent = std::fs::metadata(marker)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .is_some_and(|age| age < YOUNG);
    if recent {
        return;
    }
    // Marked first: another fwe starting meanwhile need not collect too.
    let _ = std::fs::File::create(marker);
    // In a process of its own, which no one waits for: a program's start
    // does not wait for it, its program never sees it as a child (its
    // parent, gone at once, leaves it to the host), and it is in no group
    // of the program's.
    // SAFETY: plain host calls; the process is single-threaded here (a
    // fresh start, before the guest runs), and each child only collects
    // and ends.
    unsafe {
        match libc::fork() {
            0 => {
                if libc::fork() == 0 {
                    // Out of the program's session and process group: no
                    // signal to them, and no wait for them, reaches it.
                    libc::setsid();
                    detach_descriptors();
                    collect_in(&base);
                }
                libc::_exit(0)
            }
            -1 => collect_in(&base),
            child => {
                let mut status = 0;
                while libc::waitpid(child, &mut status, 0) < 0
                    && crate::host::last_errno() == libc::EINTR
                {}
            }
        }
    }
}

/// Close every descriptor inherited, and put `/dev/null` in place of the
/// standard ones: whoever reads the output of the process that started
/// [`collect`] must not wait for it too.
fn detach_descriptors() {
    let fds: Vec<i32> = std::fs::read_dir("/dev/fd")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse().ok())
        .collect();
    for fd in fds {
        // SAFETY: closing a descriptor this process inherited (the one the
        // listing used is closed already, harmlessly closed again).
        unsafe { libc::close(fd) };
    }
    // SAFETY: opening `/dev/null`, which takes the lowest number (0), and
    // making 1 and 2 copies of it.
    unsafe {
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if null == 0 {
            libc::dup2(0, 1);
            libc::dup2(0, 2);
        }
    }
}

/// Whether `name` (past `v<FORMAT>-`) is the initial IPC namespace's
/// record of an earlier boot of the host: this boot's lasts until the host
/// restarts, as Linux's initial namespace's objects last until the machine
/// does ([`crate::sysvipc::initial`]).
fn earlier_boot_ipc(name: &[u8]) -> bool {
    name.strip_prefix(b"ipc-initial-")
        .is_some_and(|boot| boot != crate::host::boot_time().to_string().as_bytes())
}

/// [`collect`]'s work, in fwe's private directory `base`.
fn collect_in(base: &[u8]) {
    use std::collections::HashSet;
    use std::os::unix::ffi::OsStrExt;
    let base = base.to_vec();
    let os = |p: &[u8]| std::ffi::OsStr::from_bytes(p).to_owned();
    crate::procreg::collect_leftovers(YOUNG);
    // Prepared code no start has made for a month.
    crate::prepcache::collect(std::time::Duration::from_secs(30 * 24 * 3600));
    // The owners of socket nodes that are gone.
    #[cfg(target_os = "macos")]
    crate::socketowners::collect();
    let mut live: HashSet<Vec<u8>> = HashSet::new();
    for (_, r) in crate::procreg::all() {
        live.extend(r.ns);
        live.extend(r.held);
    }
    // An ended process not yet reaped keeps its numbers, while someone
    // may still reap it.
    for e in crate::procreg::all_ended() {
        if crate::reaper::reapable(&e) {
            live.extend(e.numbers.into_iter().map(|(d, _)| d));
        } else {
            crate::procreg::take_ended(&e);
        }
    }
    // A pid namespace above a live one is live too.
    let mut pending: Vec<Vec<u8>> = live.iter().cloned().collect();
    while let Some(d) = pending.pop() {
        let name = d.rsplit(|&b| b == b'/').next().unwrap_or(&[]).to_vec();
        if !name.starts_with(format!("v{FORMAT}-pid-").as_bytes()) {
            continue;
        }
        if let Ok(r) = Record::<crate::pidns::PidNs>::join(&d, 0)
            && let Some((parent, _)) = r.get().parent.clone()
            && live.insert(parent.clone())
        {
            pending.push(parent);
        }
    }
    // What the live mount tables show.
    let mut shown: HashSet<Vec<u8>> = HashSet::new();
    // The filesystems of fwe's store they show.
    let mut stores: HashSet<u64> = HashSet::new();
    let kind_of = |d: &[u8]| -> Vec<u8> {
        let name = d.rsplit(|&b| b == b'/').next().unwrap_or(&[]);
        let rest = name.strip_prefix(format!("v{FORMAT}-").as_bytes()).unwrap_or(&[]);
        rest.split(|&b| b == b'-').next().unwrap_or(&[]).to_vec()
    };
    // The initial tables are kept for the next fwe on their rootfs, and
    // their mounts with them.
    let init_tables: Vec<Vec<u8>> = std::fs::read_dir(os(&base))
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| [&base[..], b"/", e.file_name().as_bytes()].concat())
        .filter(|p| {
            p.rsplit(|&b| b == b'/')
                .next()
                .is_some_and(|n| n.starts_with(format!("v{FORMAT}-mnt-init-").as_bytes()))
        })
        .collect();
    // A namespace bound to a path in a live table (an nsfs mount) is live.
    let mut bound: Vec<Vec<u8>> = Vec::new();
    for d in live.iter().filter(|d| kind_of(d) == b"mnt").chain(init_tables.iter()) {
        if let Ok(ns) = crate::mounts::store::Ns::join(d, 0) {
            for m in &ns.table().mounts {
                match &m.source {
                    crate::mounts::Source::Ns(n) => bound.extend(n.dir.clone()),
                    crate::mounts::Source::Host(h) => {
                        shown.insert(h.clone());
                    }
                    // An overlay keeps the tmpfs its layers are in, even
                    // once that is unmounted.
                    crate::mounts::Source::Overlay(l) => {
                        for place in l.places().chain(l.work.as_ref()) {
                            let p = match place {
                                crate::overlay::Place::Host(p) => p,
                                crate::overlay::Place::Store { fs, .. } => {
                                    stores.insert(*fs);
                                    continue;
                                }
                            };
                            let Some(rest) = p.strip_prefix(&base[..]) else { continue };
                            let top = rest.split(|&b| b == b'/').find(|c| !c.is_empty());
                            if let Some(top) = top {
                                shown.insert([&base[..], b"/", top].concat());
                            }
                        }
                    }
                    crate::mounts::Source::Store(id) => {
                        stores.insert(*id);
                    }
                    crate::mounts::Source::Synthetic => {}
                }
            }
        }
    }
    live.extend(bound);
    // Each record and each entry of the directory, by name: when it was
    // made (or last changed, for a file), and whether it is a directory.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut names: std::collections::BTreeMap<Vec<u8>, (u64, bool)> = Default::default();
    for (path, made) in named::all() {
        // (Records inside another's go with it.)
        if let Some(name) = path.strip_prefix(&[&base[..], b"/"].concat()[..])
            && !name.contains(&b'/')
        {
            names.insert(name.to_vec(), (made, false));
        }
    }
    for e in std::fs::read_dir(os(&base)).into_iter().flatten().flatten() {
        let changed = e
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(now, |d| d.as_secs());
        let dir = e.file_type().is_ok_and(|t| t.is_dir());
        let at = names.entry(e.file_name().as_bytes().to_vec()).or_insert((changed, dir));
        *at = (at.0.max(changed), dir);
    }
    let mine = format!("v{FORMAT}-");
    for (name, (made, dir)) in names {
        let path = [&base[..], b"/", &name].concat();
        let young = now.saturating_sub(made) < YOUNG.as_secs();
        let gone = if let Some(rest) = name.strip_prefix(mine.as_bytes()) {
            let kind = rest.split(|&b| b == b'-').next().unwrap_or(&[]);
            match kind {
                b"mnt" | b"uts" | b"ipc" | b"net" | b"pid" | b"user" | b"cgroup"
                    if !live.contains(&path) =>
                {
                    if rest.starts_with(b"mnt-init-") {
                        // Kept while its rootfs exists, for the next fwe on it.
                        let root = crate::mounts::store::Ns::join(&path, 0).ok().and_then(|ns| {
                            ns.table()
                                .mounts
                                .iter()
                                .find(|m| m.parent == m.id)
                                .and_then(|m| m.host_path(b""))
                        });
                        root.is_none_or(|r| !std::path::Path::new(&os(&r)).is_dir())
                    } else if rest.starts_with(b"ipc-initial-") {
                        // No process names it (it is everyone's who made
                        // no other): kept while the host runs.
                        earlier_boot_ipc(rest)
                    } else {
                        kind != b"cgroup" || rest.starts_with(b"cgroup-")
                    }
                }
                // A filesystem of fwe's store no table shows and no live
                // process holds a file of.
                b"store" => {
                    let id = rest.get(6..).and_then(|h| std::str::from_utf8(h).ok());
                    match id.and_then(|h| u64::from_str_radix(h, 16).ok()) {
                        Some(id) => !stores.contains(&id) && !crate::filestore::fs::in_use(id),
                        None => true,
                    }
                }
                _ => false,
            }
        } else if name.starts_with(b"tmpfs-") || name.starts_with(b"shm-") {
            // Another fwe build's directory of a tmpfs or of a `/dev/shm`
            // (this one keeps them in its store) and their limits' files.
            true
        } else if name.starts_with(b"ptrace-") {
            // ptrace's pages are the process store's.
            true
        } else {
            // Another fwe build's: `v<n>-` with another format.
            name.first() == Some(&b'v')
                && name[1..].iter().take_while(|b| b.is_ascii_digit()).count() > 0
                && !name.starts_with(mine.as_bytes())
        };
        if gone && !young {
            remove(&path, dir);
        }
    }
}

/// Remove the record named `path`, the records inside it, and its host
/// directory (`dir`) or file.
pub fn remove(path: &[u8], dir: bool) {
    use std::os::unix::ffi::OsStrExt;
    let name = path.rsplit(|&b| b == b'/').next().unwrap_or(&[]);
    if name.starts_with(format!("v{FORMAT}-ipc-").as_bytes()) {
        crate::sysvipc::forget(path);
    }
    if let Some(id) = name
        .strip_prefix(format!("v{FORMAT}-store-").as_bytes())
        .and_then(|h| std::str::from_utf8(h).ok())
        .and_then(|h| u64::from_str_radix(h, 16).ok())
    {
        crate::filestore::fs::remove(id);
    }
    let inside = [path, b"/"].concat();
    for (name, _) in named::all() {
        if name.starts_with(&inside) {
            named::remove(&name);
        }
    }
    named::remove(path);
    let p = std::ffi::OsStr::from_bytes(path);
    if dir {
        let _ = std::fs::remove_dir_all(p);
    } else {
        let _ = std::fs::remove_file(p);
    }
}

#[cfg(test)]
mod collect_tests {
    use super::*;

    /// The initial IPC namespace's record is this boot's to keep, however
    /// long since it changed; an earlier boot's goes.
    #[test]
    fn the_initial_ipc_namespace_lasts_while_the_host_runs() {
        let now = format!("ipc-initial-{}", crate::host::boot_time());
        assert!(!earlier_boot_ipc(now.as_bytes()));
        assert!(earlier_boot_ipc(b"ipc-initial-1"));
        assert!(!earlier_boot_ipc(b"ipc-1234-5678-0"));
    }
}
