//! Guest descriptors of the store's files.
//!
//! A descriptor stands on the host's `/dev/null`, opened with the guest's
//! access mode and status flags: the host keeps the open file
//! description's position and flags, shared by its duplicates, the fork
//! children that inherit it and the processes it is passed to, as Linux
//! shares an open file's. Its mark ([`Mark::Store`]) numbers an entry of
//! this process's table, which names the file (its filesystem and inode)
//! and the description (an id no other description has, which the
//! description's locks are owned by).
//!
//! Each file counts the descriptors each process has of it ([`sync`]): a
//! file with no names lives while some process holds it, as Linux's does,
//! and goes with the last descriptor or the last holder's end (the
//! holders of processes that ended are reaped: [`sweep`]). A file sent to
//! another process (`SCM_RIGHTS`) is held by the message, a holder of its
//! own ([`IN_FLIGHT`]) the receiver lets go of once it counted itself, so
//! the file lives on whether or not the sender does. (A message never
//! received holds its files until the store goes: none of its processes
//! can tell it was lost.)
//!
//! While this process holds a file, it keeps its mapping of the file's
//! data ([`super::data::keep`]), so reads and writes map nothing.

use super::fs::{self as sfs, Fs};
use super::tree::Ino;
use crate::fdmarks::{self, Mark};
use crate::snapshot::{Dec, Enc};
use fwe_abi::errno;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

/// A file of the store.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct File {
    pub fs: u64,
    pub ino: Ino,
}

impl File {
    pub fn fs(&self) -> Result<Arc<Fs>, i32> {
        sfs::get(self.fs, false)
    }
}

/// An open file description: its file, and its id.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Desc {
    file: File,
    id: u64,
}

/// The process's descriptions, by their marks' numbers.
pub(crate) static DESCS: Mutex<BTreeMap<u32, Desc>> = Mutex::new(BTreeMap::new());
static NEXT_KEY: AtomicU32 = AtomicU32::new(1);

/// Whether the process ever had a descriptor of the store: until it has,
/// a call asking about a descriptor looks no further.
static ANY: AtomicBool = AtomicBool::new(false);

/// How many descriptors of each file the process has, as the file was
/// last told ([`sync`]), and the data object it keeps mapped for each.
pub(crate) static HELD: Mutex<BTreeMap<File, (u32, u64)>> = Mutex::new(BTreeMap::new());

fn descs<R>(f: impl FnOnce(&mut BTreeMap<u32, Desc>) -> R) -> R {
    f(&mut DESCS.lock().unwrap_or_else(|e| e.into_inner()))
}

fn key_of(fd: i32) -> Option<u32> {
    if fd < 0 || !ANY.load(Ordering::Relaxed) {
        return None;
    }
    match fdmarks::marked(fd) {
        Some(Mark::Store(k)) => Some(k),
        _ => None,
    }
}

/// The file `fd` is a descriptor of, if it is one of the store's.
pub fn of(fd: i32) -> Option<File> {
    let k = key_of(fd)?;
    descs(|m| m.get(&k).map(|d| d.file))
}

/// The id of the open file description `fd` is, if it is one of the
/// store's.
pub fn description(fd: i32) -> Option<u64> {
    let k = key_of(fd)?;
    descs(|m| m.get(&k).map(|d| d.id))
}

/// Linux's open flags as the host's, for the stand-in.
fn host_flags(flags: u64) -> i32 {
    use fwe_abi::fcntl::{O_APPEND, O_CLOEXEC, O_NONBLOCK};
    let mut h = match flags & 3 {
        1 => libc::O_WRONLY,
        2 => libc::O_RDWR,
        _ => libc::O_RDONLY,
    };
    for (l, host) in
        [(O_APPEND, libc::O_APPEND), (O_NONBLOCK, libc::O_NONBLOCK), (O_CLOEXEC, libc::O_CLOEXEC)]
    {
        if flags & l != 0 {
            h |= host;
        }
    }
    h
}

/// A new description of `file`, open with Linux's `flags` (its access
/// mode, `O_APPEND`, `O_NONBLOCK`, `O_CLOEXEC`): its descriptor, the
/// lowest free (`EMFILE` past the limit).
pub fn open(file: File, flags: u64) -> Result<i32, i32> {
    // SAFETY: a NUL-terminated path; the descriptor is this call's.
    let fd = unsafe { libc::open(c"/dev/null".as_ptr(), host_flags(flags)) };
    if fd < 0 {
        return Err(crate::host::errno_to_linux(crate::host::last_errno()));
    }
    if crate::fdtable::over_limit(&[fd]) {
        // SAFETY: the descriptor opened above.
        unsafe { libc::close(fd) };
        return Err(errno::EMFILE);
    }
    adopt(fd, file, crate::shared::unique());
    sync(&[]);
    Ok(fd)
}

/// The number of the description a re-executed fwe was handed its program
/// on ([`adopt_exe`]): one no other description takes.
const EXE_KEY: u32 = u32::MAX;

/// In an fwe re-executed for a guest's `execve` of a program with no path
/// (a memfd), before the guest's state is: host descriptor `fd`, fwe's own,
/// is description `id` of `file`, which this process holds already (its
/// counts carry over the host `execve`).
pub fn adopt_exe(fd: i32, file: File, id: u64) {
    ANY.store(true, Ordering::Relaxed);
    descs(|m| m.insert(EXE_KEY, Desc { file, id }));
    fdmarks::mark(fd, Mark::Store(EXE_KEY));
}

/// Host descriptor `fd` (a `/dev/null`) is description `id` of `file`
/// (the caller then counts it: [`sync`]).
fn adopt(fd: i32, file: File, id: u64) {
    ANY.store(true, Ordering::Relaxed);
    let k = NEXT_KEY.fetch_add(1, Ordering::Relaxed);
    descs(|m| m.insert(k, Desc { file, id }));
    fdmarks::mark(fd, Mark::Store(k));
}

/// Tell each file whose count of this process's descriptors changed what
/// it is now: every open descriptor marked as the store's but those in
/// `skip` (which an `exec` closes). The numbers no descriptor has any more
/// are forgotten, and the mappings of files no longer held go.
pub fn sync(skip: &[i32]) {
    if !ANY.load(Ordering::Relaxed) {
        return;
    }
    let mut now: BTreeMap<File, u32> = BTreeMap::new();
    let mut keys = BTreeSet::new();
    for (fd, mark) in fdmarks::marks() {
        let Mark::Store(k) = mark else { continue };
        if skip.contains(&fd) || key_of(fd) != Some(k) {
            continue;
        }
        keys.insert(k);
        if let Some(d) = descs(|m| m.get(&k).copied()) {
            *now.entry(d.file).or_default() += 1;
        }
    }
    descs(|m| m.retain(|k, _| keys.contains(k)));
    let mut held = HELD.lock().unwrap_or_else(|e| e.into_inner());
    let me = crate::sysvipc::me();
    let files: BTreeSet<File> = held.keys().chain(now.keys()).copied().collect();
    for file in files {
        let n = now.get(&file).copied().unwrap_or(0);
        let (before, kept) = held.get(&file).copied().unwrap_or((0, 0));
        if before == n {
            continue;
        }
        let Ok(fs) = file.fs() else {
            held.remove(&file);
            continue;
        };
        let told = fs.lock().and_then(|mut t| {
            let object = t.data(file.ino)?;
            let gone = t.hold(file.ino, me, n)?;
            Ok((object, gone))
        });
        let object = match told {
            Ok((object, gone)) => {
                if let Some(o) = gone.data {
                    super::data::remove(o);
                }
                object
            }
            Err(_) => 0,
        };
        if n == 0 {
            super::data::let_go(kept);
            held.remove(&file);
        } else {
            let kept = if kept == 0 && object != 0 {
                super::data::keep(object);
                object
            } else {
                kept
            };
            held.insert(file, (n, kept));
        }
    }
}

/// `file`'s data is object `object` now (its first write made it): kept
/// mapped if this process holds the file.
pub fn made_data(file: File, object: u64) {
    let mut held = HELD.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(e) = held.get_mut(&file)
        && e.1 == 0
    {
        super::data::keep(object);
        e.1 = object;
    }
}

/// The host pid of a message's holding: its start is the message's token.
const IN_FLIGHT: i32 = 0;

/// Forget the holders of `fs`'s files with no names that have ended: the
/// files only they held go.
pub fn sweep(fs: &Fs) {
    let Ok(mut t) = fs.lock() else { return };
    for ino in t.unnamed() {
        let alive = |p: (i32, u64)| p.0 == IN_FLIGHT || crate::procreg::alive(p);
        if let Ok(gone) = t.reap(ino, alive)
            && let Some(o) = gone.data
        {
            super::data::remove(o);
        }
    }
}

/// Descriptor `fd` is about to be closed: if it is the store's, what to do
/// once it is (count the process's descriptors again).
pub fn closing(fd: i32) -> Option<impl FnOnce()> {
    key_of(fd)?;
    Some(|| sync(&[]))
}

/// In the parent, after the host `fork` made `child`: the files this
/// process holds are held by the child as many times (unless it counted
/// itself already), so that this process closing its own or ending frees
/// none the child has.
pub fn forked(child: i32) {
    if let Some(start) = crate::procreg::start_time(child) {
        hand_on((child, start));
    }
}

/// In a fork child, as it starts: the same, from its side, should it go on
/// before its parent counted it.
pub fn forked_child() {
    hand_on(crate::sysvipc::me());
}

fn hand_on(p: (i32, u64)) {
    let held: Vec<(File, u32)> =
        HELD.lock().unwrap_or_else(|e| e.into_inner()).iter().map(|(f, e)| (*f, e.0)).collect();
    for (file, n) in held {
        if let Ok(fs) = file.fs()
            && let Ok(mut t) = fs.lock()
        {
            let _ = t.hold_unless_counted(file.ino, p, n);
        }
    }
}

/// Write the process's descriptions into a fork snapshot or exec state
/// (the descriptors go with it: [`crate::fdmarks`]).
pub(crate) fn save(e: &mut Enc) {
    e.bool(ANY.load(Ordering::Relaxed));
    e.u32(NEXT_KEY.load(Ordering::Relaxed));
    let d = DESCS.lock().unwrap_or_else(|e| e.into_inner());
    e.u64(d.len() as u64);
    for (&k, desc) in d.iter() {
        e.u32(k);
        e.u64(desc.file.fs);
        e.u64(desc.file.ino);
        e.u64(desc.id);
    }
    let h = HELD.lock().unwrap_or_else(|e| e.into_inner());
    e.u64(h.len() as u64);
    for (f, (n, _)) in h.iter() {
        e.u64(f.fs);
        e.u64(f.ino);
        e.u32(*n);
    }
}

/// What [`save`] wrote, in the new process (which maps no data yet).
pub(crate) fn load(d: &mut Dec) {
    ANY.store(d.bool(), Ordering::Relaxed);
    NEXT_KEY.store(d.u32(), Ordering::Relaxed);
    let n = d.count(28);
    let mut descs = DESCS.lock().unwrap_or_else(|e| e.into_inner());
    for _ in 0..n {
        let k = d.u32();
        let file = File { fs: d.u64(), ino: d.u64() };
        descs.insert(k, Desc { file, id: d.u64() });
    }
    let n = d.count(20);
    let mut held = HELD.lock().unwrap_or_else(|e| e.into_inner());
    for _ in 0..n {
        let file = File { fs: d.u64(), ino: d.u64() };
        held.insert(file, (d.u32(), 0));
    }
}

/// What a descriptor of the store takes to another process: its file and
/// description, and the token of the message's holding of the file.
#[cfg(not(target_os = "linux"))]
pub(crate) fn export(fd: i32) -> Option<crate::scm::Export> {
    let k = key_of(fd)?;
    let d = descs(|m| m.get(&k).copied())?;
    let token = crate::shared::unique();
    let held = d.file.fs().and_then(|fs| fs.lock()?.hold(d.file.ino, (IN_FLIGHT, token), 1));
    if held.is_err() {
        return None;
    }
    let mut e = Enc::default();
    e.u64(d.file.fs);
    e.u64(d.file.ino);
    e.u64(d.id);
    e.u64(token);
    Some(crate::scm::Export {
        kind: crate::scm::kind::STORE,
        state: e.into_bytes(),
        companions: Vec::new(),
        placeholder: false,
    })
}

/// A descriptor received with what [`export`] sent: the same description
/// here.
#[cfg(not(target_os = "linux"))]
pub(crate) fn import(fd: i32, d: &mut Dec) -> bool {
    let file = File { fs: d.u64(), ino: d.u64() };
    let (id, token) = (d.u64(), d.u64());
    let Ok(fs) = file.fs() else { return false };
    adopt(fd, file, id);
    sync(&[]);
    let_go_in_flight(&fs, file.ino, token);
    true
}

/// A message that held `ino` of `fs` as `token` (an [`export`]'s) was taken
/// or never sent.
#[cfg(not(target_os = "linux"))]
fn let_go_in_flight(fs: &Fs, ino: Ino, token: u64) {
    if let Ok(mut t) = fs.lock()
        && let Ok(gone) = t.hold(ino, (IN_FLIGHT, token), 0)
        && let Some(o) = gone.data
    {
        super::data::remove(o);
    }
}

/// A message [`export`] described the descriptor for was not sent: its
/// holding goes.
#[cfg(not(target_os = "linux"))]
pub(crate) fn unsent(state: &[u8]) {
    let mut d = Dec::new(state);
    let file = File { fs: d.u64(), ino: d.u64() };
    let (_, token) = (d.u64(), d.u64());
    if let Ok(fs) = file.fs() {
        let_go_in_flight(&fs, file.ino, token);
    }
}
