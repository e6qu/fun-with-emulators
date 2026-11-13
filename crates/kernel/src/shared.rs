//! State that every fwe process sees: a record in fwe's private directory
//! on the host, as a kernel keeps state every process sees in its own
//! memory. Mount tables, namespaces and the cgroup tree are such records.
//!
//! A record is a directory holding its data and a generation count each
//! process maps, so a process rereads the data only when another has
//! changed it. Each change, made under a lock, counts a generation. A type
//! that keeps its changes ([`Data::changes`]) has each appended to a
//! journal beside the data, which a process applies to its copy, until the
//! journal outgrows the data and the data is written whole again; others
//! are written whole each time. A record of thousands of objects (System V
//! IPC's) so costs a change what the change holds, not what the record
//! does.

use crate::host::{errno_to_linux, last_errno};
use crate::snapshot::{Dec, Enc};
use fwe_abi::errno;
use std::ffi::CString;
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
    /// Apply changes [`Data::changes`] encoded (keeping none of them as
    /// changes of its own).
    fn apply(&mut self, _d: &mut Dec) {}
}

/// The size a journal may reach before the data is written whole, when
/// the data is smaller.
const JOURNAL_MIN: u64 = 64 << 10;

/// The bytes of the file at host path `p`.
fn read_path(p: &[u8]) -> Result<Vec<u8>, i32> {
    use std::os::unix::ffi::OsStrExt;
    std::fs::read(std::ffi::OsStr::from_bytes(p))
        .map_err(|e| e.raw_os_error().map_or(errno::EIO, errno_to_linux))
}

fn e() -> i32 {
    errno_to_linux(last_errno())
}

fn c(p: &[u8]) -> Result<CString, i32> {
    CString::new(p).map_err(|_| errno::EINVAL)
}

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

/// Sleep up to `slice` while the generation word reads `seen` (its low
/// half, which every change changes), a shared host address wait any
/// process's change ends ([`wake_all`]).
fn wait_word(word: &AtomicU64, seen: u64, slice: std::time::Duration) {
    #[cfg(target_os = "macos")]
    // SAFETY: the record's mapped generation word; the host sleeps while
    // its low half still reads `seen`'s.
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

/// Wake every process waiting for the record's generation to change.
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
pub const FORMAT: u32 = 20;

/// A name no other record has: the kind, this process and a count.
fn fresh_name(kind: &str) -> String {
    static N: AtomicU64 = AtomicU64::new(0);
    // SAFETY: getpid cannot fail.
    let pid = unsafe { libc::getpid() };
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
            if crate::host::last_errno() != libc::EWOULDBLOCK || now() - start > 1_000_000_000 {
                libc::flock(fd, libc::LOCK_EX);
                break;
            }
            libc::sched_yield();
        }
    }
    crate::host::set_errno(saved);
}

/// One record, as this process sees it.
pub struct Record<T: Data> {
    /// The record's directory.
    dir: Vec<u8>,
    /// Its identity (a namespace's number in `/proc/self/ns`).
    id: u64,
    /// The shared generation count.
    generation: &'static AtomicU64,
    /// The data as last read, and the generation it was read at.
    cache: Mutex<(u64, Arc<T>)>,
}

impl<T: Data> std::fmt::Debug for Record<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Record({})", String::from_utf8_lossy(&self.dir))
    }
}

impl<T: Data> Record<T> {
    /// The record called `name`, made with `initial` if it does not exist.
    /// `id` is its identity, or 0 for one from its directory.
    pub fn named(name: &str, id: u64, initial: impl FnOnce() -> T) -> Result<Record<T>, i32> {
        let mut dir = crate::fs::shm::user_dir()?;
        dir.extend_from_slice(format!("/v{FORMAT}-{name}").as_bytes());
        Record::open_or_make(dir, id, initial)
    }

    /// The record at directory `dir`, inside another record's (whose life
    /// it shares), made with `initial` if it does not exist.
    pub fn at(dir: Vec<u8>, initial: impl FnOnce() -> T) -> Result<Record<T>, i32> {
        Record::open_or_make(dir, 0, initial)
    }

    /// A new record of `kind` holding `data` (after collecting those no
    /// process holds any more, see [`collect`]).
    pub fn fresh(kind: &str, data: T) -> Result<Record<T>, i32> {
        collect();
        Record::named(&fresh_name(kind), 0, || data)
    }

    /// The record whose directory is `dir` ([`Record::dir`]), which must
    /// exist and hold data of this kind (one a parent process had). It is
    /// never written here.
    pub fn join(dir: &[u8], id: u64) -> Result<Record<T>, i32> {
        let r = Record::open(dir.to_vec(), id, false)?;
        r.read_file().map_err(|_| errno::ENOENT)?;
        Ok(r)
    }

    fn open_or_make(dir: Vec<u8>, id: u64, initial: impl FnOnce() -> T) -> Result<Record<T>, i32> {
        let r = Record::open(dir, id, true)?;
        r.with_lock(|| {
            if r.read_file().is_err() {
                let at = r.generation() + 1;
                r.write_file(at, &initial())?;
                r.advance(at);
            }
            Ok(())
        })?;
        Ok(r)
    }

    /// The record at `dir`, made if `make`, with its generation mapped.
    fn open(dir: Vec<u8>, id: u64, make: bool) -> Result<Record<T>, i32> {
        let d = c(&dir)?;
        if make {
            // SAFETY: a NUL-terminated path in fwe's private directory.
            unsafe { libc::mkdir(d.as_ptr(), 0o700) };
        }
        let gen_path = c(&[&dir[..], b"/generation"].concat())?;
        let create = if make { libc::O_CREAT } else { 0 };
        // SAFETY: as above.
        let fd = unsafe {
            libc::open(gen_path.as_ptr(), libc::O_RDWR | create | libc::O_CLOEXEC, 0o600)
        };
        if fd < 0 {
            return Err(e());
        }
        // SAFETY: zeroed bytes are a valid `stat`; `fstat` fills it.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: plain host calls on the descriptor just opened.
        let ok = unsafe { libc::ftruncate(fd, 8) == 0 && libc::fstat(fd, &mut st) == 0 };
        if !ok {
            let err = e();
            // SAFETY: closing it again.
            unsafe { libc::close(fd) };
            return Err(err);
        }
        // SAFETY: a shared mapping of the 8-byte file, never unmapped: a
        // process has only a few records, for as long as it lives.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                8,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        // SAFETY: the mapping holds its own reference to the file.
        unsafe { libc::close(fd) };
        if p == libc::MAP_FAILED {
            return Err(e());
        }
        // SAFETY: the mapping is 8 bytes, page-aligned and lives forever.
        let generation: &'static AtomicU64 = unsafe { &*(p as *const AtomicU64) };
        let id = if id != 0 { id } else { 4026532000 + (st.st_ino as u64 & 0xffff_ffff) };
        Ok(Record { dir, id, generation, cache: Mutex::new((u64::MAX, Arc::new(T::default()))) })
    }

    pub fn dir(&self) -> &[u8] {
        &self.dir
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    fn data_path(&self) -> Vec<u8> {
        [&self.dir[..], b"/data"].concat()
    }

    fn journal_path(&self) -> Vec<u8> {
        [&self.dir[..], b"/journal"].concat()
    }

    /// The data as last written whole, and the generation it is at.
    fn read_file(&self) -> Result<(u64, T), i32> {
        let bytes = read_path(&self.data_path())?;
        let mut d = Dec::new(&bytes);
        let at = d.u64();
        let t = T::decode(&mut d);
        d.finish().map_err(|_| errno::EIO)?;
        if !t.valid() {
            return Err(errno::EIO);
        }
        Ok((at, t))
    }

    /// The generation the data written whole is at.
    fn file_generation(&self) -> Result<u64, i32> {
        use std::io::Read;
        use std::os::unix::ffi::OsStrExt;
        let mut f = std::fs::File::open(std::ffi::OsStr::from_bytes(&self.data_path()))
            .map_err(|e| e.raw_os_error().map_or(errno::EIO, errno_to_linux))?;
        let mut b = [0u8; 8];
        f.read_exact(&mut b).map_err(|_| errno::EIO)?;
        Ok(u64::from_le_bytes(b))
    }

    /// The journal's changes after generation `after`, one per generation
    /// from `after + 1` on, each with its generation. A change written
    /// again for the same generation (its writer ended before the change
    /// counted) stands for the one before it.
    fn journal_after(&self, after: u64) -> Vec<(u64, Vec<u8>)> {
        let Ok(bytes) = read_path(&self.journal_path()) else { return Vec::new() };
        let mut d = Dec::new(&bytes);
        let mut out: Vec<(u64, Vec<u8>)> = Vec::new();
        while !d.at_end() {
            let (at, body) = (d.u64(), d.bytes());
            if !d.whole() {
                // One being written as this read.
                break;
            }
            out.retain(|&(g, _)| g < at);
            if at > after {
                out.push((at, body));
            }
        }
        out
    }

    /// The data at generation `seen` and the changes after it, applied:
    /// the data and the generation it is now at (`Err` for changes
    /// missing between).
    fn apply_after(&self, seen: u64, base: &T) -> Result<(u64, T), i32> {
        let changes = self.journal_after(seen);
        let mut t = base.clone();
        let mut at = seen;
        for (g, body) in changes {
            if g != at + 1 {
                return Err(errno::EIO);
            }
            let mut d = Dec::new(&body);
            t.apply(&mut d);
            d.finish().map_err(|_| errno::EIO)?;
            at = g;
        }
        Ok((at, t))
    }

    /// The data as it is now and the generation it is at: `cached` (at
    /// generation `seen`) brought up to date from the journal when it
    /// holds every change since, else read whole. What a change made
    /// meanwhile tore is read again.
    fn read_current(&self, seen: u64, cached: &Arc<T>) -> Result<(u64, Arc<T>), i32> {
        let mut last = Err(errno::EIO);
        for _ in 0..100 {
            let now = self.generation.load(Ordering::SeqCst);
            let read = match self.file_generation() {
                Ok(whole) if seen != u64::MAX && whole <= seen => self.apply_after(seen, cached),
                Ok(_) => self.read_file().and_then(|(whole, t)| self.apply_after(whole, &t)),
                Err(e) => Err(e),
            };
            match read {
                Ok((at, t)) if at == now => return Ok((at, Arc::new(t))),
                Ok((at, t)) => last = Ok((at, Arc::new(t))),
                Err(e) => last = Err(e),
            }
            std::thread::yield_now();
        }
        last
    }

    /// Under the lock: write `t` whole at generation `at`.
    fn write_file(&self, at: u64, t: &T) -> Result<(), i32> {
        use std::os::unix::ffi::OsStrExt;
        let mut enc = Enc::new();
        enc.u64(at);
        t.encode(&mut enc);
        // SAFETY: getpid cannot fail.
        let pid = unsafe { libc::getpid() };
        let tmp = [&self.data_path()[..], format!(".{pid}").as_bytes()].concat();
        std::fs::write(std::ffi::OsStr::from_bytes(&tmp), enc.into_bytes())
            .map_err(|e| e.raw_os_error().map_or(errno::EIO, errno_to_linux))?;
        let (from, to) = (c(&tmp)?, c(&self.data_path())?);
        // SAFETY: NUL-terminated paths in the record's directory.
        if unsafe { libc::rename(from.as_ptr(), to.as_ptr()) } != 0 {
            return Err(e());
        }
        Ok(())
    }

    /// Under the lock: the change made at generation `at`, appended to
    /// the journal in one write.
    fn append_journal(&self, at: u64, body: Vec<u8>) -> Result<(), i32> {
        use std::io::Write;
        use std::os::unix::ffi::OsStrExt;
        let mut enc = Enc::new();
        enc.u64(at);
        enc.bytes(&body);
        std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(std::ffi::OsStr::from_bytes(&self.journal_path()))
            .and_then(|mut f| f.write_all(&enc.into_bytes()))
            .map_err(|e| e.raw_os_error().map_or(errno::EIO, errno_to_linux))
    }

    /// Under the lock: the generation moves to `at`, for every process.
    fn advance(&self, at: u64) {
        self.generation.store(at, Ordering::SeqCst);
        wake_all(self.generation);
    }

    /// Under the lock: the data as it is now, the cached copy taken when
    /// it is current (no other process changed it since), else read.
    fn take_locked(&self) -> Result<T, i32> {
        let now = self.generation.load(Ordering::SeqCst);
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        let held = std::mem::replace(&mut *cache, (u64::MAX, Arc::new(T::default())));
        if held.0 == now {
            return Ok(Arc::try_unwrap(held.1).unwrap_or_else(|a| (*a).clone()));
        }
        let (_, t) = self.read_current(held.0, &held.1)?;
        Ok(Arc::try_unwrap(t).unwrap_or_else(|a| (*a).clone()))
    }

    /// Under the lock: `t` is the data now, for every process. A type
    /// that keeps its changes has them appended to the journal; the data
    /// is written whole once the journal outgrows it.
    fn put_locked(&self, mut t: T) -> Result<(), i32> {
        use std::os::unix::ffi::OsStrExt;
        let at = self.generation.load(Ordering::SeqCst) + 1;
        let mut changes = Enc::new();
        let kept = t.changes(&mut changes);
        let size =
            |p: &[u8]| std::fs::metadata(std::ffi::OsStr::from_bytes(p)).map_or(0, |m| m.len());
        let (whole, journal) = (size(&self.data_path()), size(&self.journal_path()));
        let changes = changes.into_bytes();
        if kept && whole > 0 && journal + changes.len() as u64 <= whole.max(JOURNAL_MIN) {
            self.append_journal(at, changes)?;
        } else {
            self.write_file(at, &t)?;
            if journal > 0 {
                let _ = std::fs::write(std::ffi::OsStr::from_bytes(&self.journal_path()), b"");
            }
        }
        self.advance(at);
        *self.cache.lock().unwrap_or_else(|e| e.into_inner()) = (at, Arc::new(t));
        Ok(())
    }

    /// Under the lock: `t`, which `f` left as it was, is the cached copy
    /// again.
    fn restore_locked(&self, mut t: T) {
        t.changes(&mut Enc::new());
        *self.cache.lock().unwrap_or_else(|e| e.into_inner()) =
            (self.generation.load(Ordering::SeqCst), Arc::new(t));
    }

    /// Run `f` holding the record's lock.
    fn with_lock<R>(&self, f: impl FnOnce() -> Result<R, i32>) -> Result<R, i32> {
        let lock = c(&[&self.dir[..], b"/lock"].concat())?;
        // SAFETY: a NUL-terminated path in the record's directory.
        let fd = unsafe {
            libc::open(lock.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC, 0o600)
        };
        if fd < 0 {
            return Err(e());
        }
        lock_exclusive(fd);
        let r = f();
        // SAFETY: plain host call on the descriptor just opened; the lock
        // goes with it.
        unsafe { libc::close(fd) };
        r
    }

    /// The record's generation: it changes with every change of its data.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
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
            wait_word(self.generation, seen, slice);
        }
    }

    /// The data as it is now.
    pub fn get(&self) -> Arc<T> {
        let now = self.generation.load(Ordering::SeqCst);
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if cache.0 != now
            && let Ok(fresh) = self.read_current(cache.0, &cache.1)
        {
            *cache = fresh;
        }
        cache.1.clone()
    }

    /// Change the data with `f`, for every process.
    pub fn update<R>(&self, f: impl FnOnce(&mut T) -> Result<R, i32>) -> Result<R, i32> {
        self.with_lock(|| {
            let mut t = self.take_locked()?;
            let r = f(&mut t)?;
            self.put_locked(t)?;
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
        self.with_lock(|| {
            let mut t = self.take_locked()?;
            let (r, changed) = f(&mut t)?;
            if changed {
                self.put_locked(t)?;
            } else {
                self.restore_locked(t);
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
/// gone, and the tracing mailboxes of processes that are gone.
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

/// [`collect`]'s work, in fwe's private directory `base`.
fn collect_in(base: &[u8]) {
    use std::collections::HashSet;
    use std::os::unix::ffi::OsStrExt;
    let base = base.to_vec();
    let os = |p: &[u8]| std::ffi::OsStr::from_bytes(p).to_owned();
    crate::procreg::collect_leftovers(YOUNG);
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
                        for p in l.paths().chain(l.work.as_deref()) {
                            let Some(rest) = p.strip_prefix(&base[..]) else { continue };
                            let top = rest.split(|&b| b == b'/').find(|c| !c.is_empty());
                            if let Some(top) = top {
                                shown.insert([&base[..], b"/", top].concat());
                            }
                        }
                    }
                    crate::mounts::Source::Synthetic => {}
                }
            }
        }
    }
    live.extend(bound);
    let Ok(entries) = std::fs::read_dir(os(&base)) else { return };
    let mine = format!("v{FORMAT}-");
    for e in entries.flatten() {
        let name = e.file_name().as_bytes().to_vec();
        let path = [&base[..], b"/", &name].concat();
        let young = || {
            e.metadata()
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.elapsed().ok())
                .is_none_or(|age| age < YOUNG)
        };
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
                    } else {
                        kind != b"cgroup" || rest.starts_with(b"cgroup-")
                    }
                }
                _ => false,
            }
        } else if let Some(dir) =
            name.strip_prefix(b"tmpfs-").and_then(|n| n.strip_suffix(b".limit"))
        {
            // A tmpfs's size limit goes with it.
            !shown.contains(&[&base[..], b"/tmpfs-", dir].concat())
        } else if name.starts_with(b"tmpfs-") || name.starts_with(b"shm-") {
            // A tmpfs, or a rootfs's `/dev/shm`, that no table shows.
            !shown.contains(&path)
        } else if name.starts_with(b"ptrace-") {
            crate::ptrace::leftover(&name)
        } else {
            // Another fwe build's: `v<n>-` with another format.
            name.first() == Some(&b'v')
                && name[1..].iter().take_while(|b| b.is_ascii_digit()).count() > 0
                && !name.starts_with(mine.as_bytes())
        };
        if gone && !young() {
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                let _ = std::fs::remove_dir_all(os(&path));
            } else {
                let _ = std::fs::remove_file(os(&path));
            }
        }
    }
}
