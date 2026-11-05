//! State that every fwe process sees: a record in fwe's private directory
//! on the host, as a kernel keeps state every process sees in its own
//! memory. Mount tables, namespaces and the cgroup tree are such records.
//!
//! A record is a directory holding its data (replaced whole by each change,
//! under a lock) and a generation count each process maps, so a process
//! rereads the data only when another has changed it.

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
}

fn e() -> i32 {
    errno_to_linux(last_errno())
}

fn c(p: &[u8]) -> Result<CString, i32> {
    CString::new(p).map_err(|_| errno::EINVAL)
}

/// FNV-1a: stable across processes and fwe builds.
pub fn hash(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf29ce484222325u64, |h, &b| (h ^ b as u64).wrapping_mul(0x100000001b3))
}

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
        dir.push(b'/');
        dir.extend_from_slice(name.as_bytes());
        Record::open_or_make(dir, id, initial)
    }

    /// A new record of `kind` holding `data`.
    pub fn fresh(kind: &str, data: T) -> Result<Record<T>, i32> {
        Record::named(&fresh_name(kind), 0, || data)
    }

    /// The record whose directory is `dir` ([`Record::dir`]), which must
    /// exist (one a parent process had).
    pub fn join(dir: &[u8], id: u64) -> Result<Record<T>, i32> {
        let d = c(&[dir, b"/data"].concat())?;
        // SAFETY: zeroed bytes are a valid `stat`; `stat` fills it.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a NUL-terminated path and a valid out-parameter.
        if unsafe { libc::stat(d.as_ptr(), &mut st) } != 0 {
            return Err(errno::ENOENT);
        }
        Record::open_or_make(dir.to_vec(), id, T::default)
    }

    fn open_or_make(dir: Vec<u8>, id: u64, initial: impl FnOnce() -> T) -> Result<Record<T>, i32> {
        let d = c(&dir)?;
        // SAFETY: a NUL-terminated path in fwe's private directory.
        unsafe { libc::mkdir(d.as_ptr(), 0o700) };
        let gen_path = c(&[&dir[..], b"/generation"].concat())?;
        // SAFETY: as above.
        let fd = unsafe {
            libc::open(gen_path.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC, 0o600)
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
        let r =
            Record { dir, id, generation, cache: Mutex::new((u64::MAX, Arc::new(T::default()))) };
        r.with_lock(|| {
            if r.read_file().is_err() {
                r.write_file(&initial())?;
            }
            Ok(())
        })?;
        Ok(r)
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

    fn read_file(&self) -> Result<T, i32> {
        use std::os::unix::ffi::OsStrExt;
        let bytes = std::fs::read(std::ffi::OsStr::from_bytes(&self.data_path()))
            .map_err(|e| e.raw_os_error().map_or(errno::EIO, errno_to_linux))?;
        let mut d = Dec::new(&bytes);
        let t = T::decode(&mut d);
        d.finish().map_err(|_| errno::EIO)?;
        if !t.valid() {
            return Err(errno::EIO);
        }
        Ok(t)
    }

    fn write_file(&self, t: &T) -> Result<(), i32> {
        use std::os::unix::ffi::OsStrExt;
        let mut enc = Enc::new();
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
        self.generation.fetch_add(1, Ordering::SeqCst);
        Ok(())
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
        // SAFETY: plain host calls on the descriptor just opened; the lock
        // goes with it.
        unsafe { libc::flock(fd, libc::LOCK_EX) };
        let r = f();
        // SAFETY: as above.
        unsafe { libc::close(fd) };
        r
    }

    /// The data as it is now.
    pub fn get(&self) -> Arc<T> {
        let now = self.generation.load(Ordering::SeqCst);
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if cache.0 != now
            && let Ok(t) = self.read_file()
        {
            *cache = (now, Arc::new(t));
        }
        cache.1.clone()
    }

    /// Change the data with `f`, for every process.
    pub fn update<R>(&self, f: impl FnOnce(&mut T) -> Result<R, i32>) -> Result<R, i32> {
        self.with_lock(|| {
            let mut t = self.read_file()?;
            let r = f(&mut t)?;
            self.write_file(&t)?;
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
