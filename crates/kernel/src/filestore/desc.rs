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
use super::tree::{self, Ino};
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

/// An open file description: its file, its id, and whether it only
/// names the file (`O_PATH`).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Desc {
    file: File,
    id: u64,
    path: bool,
}

/// The process's descriptions, by their marks' numbers.
pub(crate) static DESCS: Mutex<BTreeMap<u32, Desc>> = Mutex::new(BTreeMap::new());

/// Where each description opened by a name was opened: the directory and
/// the name, by its mark's number (what inotify tells a watched directory
/// of its file's use).
pub(crate) static PLACES: Mutex<BTreeMap<u32, (Ino, Vec<u8>)>> = Mutex::new(BTreeMap::new());
static NEXT_KEY: AtomicU32 = AtomicU32::new(1);

/// Whether the process ever had a descriptor of the store: until it has,
/// a call asking about a descriptor looks no further.
static ANY: AtomicBool = AtomicBool::new(false);

/// The open file descriptions of a file the process has descriptors of,
/// and how many of each.
type Counts = Vec<(u64, u32)>;

/// The descriptions of each file the process has, as the file was last
/// told ([`sync`]), and the data object it keeps mapped for each.
pub(crate) static HELD: Mutex<BTreeMap<File, (Counts, u64)>> = Mutex::new(BTreeMap::new());

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

/// Whether `fd` is a descriptor of the store that only names its file
/// (`O_PATH`).
pub fn is_path(fd: i32) -> bool {
    key_of(fd).is_some_and(|k| descs(|m| m.get(&k).is_some_and(|d| d.path)))
}

/// Descriptor `fd` of the store was opened as `name` in directory `dir`.
pub fn set_place(fd: i32, dir: Ino, name: &[u8]) {
    if let Some(k) = key_of(fd) {
        PLACES.lock().unwrap_or_else(|e| e.into_inner()).insert(k, (dir, name.to_vec()));
    }
}

/// Where descriptor `fd` of the store was opened, if by a name: the
/// directory and the name.
pub fn place(fd: i32) -> Option<(Ino, Vec<u8>)> {
    let k = key_of(fd)?;
    PLACES.lock().unwrap_or_else(|e| e.into_inner()).get(&k).cloned()
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

/// An id for a new open file description, which no other has, open with
/// Linux's `flags`: one open for writing is marked so ([`tree::WRITER`]).
pub fn new_id(flags: u64) -> u64 {
    let writes = flags & fwe_abi::fcntl::O_ACCMODE != 0 && flags & fwe_abi::fcntl::O_PATH == 0;
    crate::shared::unique() & !tree::WRITER | if writes { tree::WRITER } else { 0 }
}

/// A new description of `file`, `id` ([`new_id`]), open with Linux's
/// `flags` (its access mode, `O_APPEND`, `O_NONBLOCK`, `O_CLOEXEC`): its
/// descriptor, the lowest free (`EMFILE` past the limit).
pub fn open(file: File, flags: u64, id: u64) -> Result<i32, i32> {
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
    adopt(fd, file, id, flags & fwe_abi::fcntl::O_PATH != 0);
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
    descs(|m| m.insert(EXE_KEY, Desc { file, id, path: false }));
    fdmarks::mark(fd, Mark::Store(EXE_KEY));
}

/// Host descriptor `fd` (a `/dev/null`) is description `id` of `file`
/// (the caller then counts it: [`sync`]).
fn adopt(fd: i32, file: File, id: u64, path: bool) {
    ANY.store(true, Ordering::Relaxed);
    let k = NEXT_KEY.fetch_add(1, Ordering::Relaxed);
    descs(|m| m.insert(k, Desc { file, id, path }));
    fdmarks::mark(fd, Mark::Store(k));
}

/// Tell each file whose count of this process's descriptors changed what
/// it is now: every open descriptor marked as the store's but those in
/// `skip` (which an `exec` closes). The numbers no descriptor has any more
/// are forgotten, and the mappings of files no longer held go. A file the
/// process has fewer descriptors of than before (one was closed) is no
/// longer locked by the process's record locks, as on Linux.
pub fn sync(skip: &[i32]) {
    if !ANY.load(Ordering::Relaxed) {
        return;
    }
    let mut now: BTreeMap<File, BTreeMap<u64, u32>> = BTreeMap::new();
    let mut keys = BTreeSet::new();
    for (fd, mark) in fdmarks::marks() {
        let Mark::Store(k) = mark else { continue };
        if skip.contains(&fd) || key_of(fd) != Some(k) {
            continue;
        }
        keys.insert(k);
        if let Some(d) = descs(|m| m.get(&k).copied()) {
            *now.entry(d.file).or_default().entry(d.id).or_default() += 1;
        }
    }
    descs(|m| m.retain(|k, _| keys.contains(k)));
    PLACES.lock().unwrap_or_else(|e| e.into_inner()).retain(|k, _| keys.contains(k));
    let mut held = HELD.lock().unwrap_or_else(|e| e.into_inner());
    let me = crate::sysvipc::me();
    let files: BTreeSet<File> = held.keys().chain(now.keys()).copied().collect();
    for file in files {
        let n: Counts =
            now.get(&file).map(|m| m.iter().map(|(&d, &c)| (d, c)).collect()).unwrap_or_default();
        let (before, kept) = held.get(&file).cloned().unwrap_or_default();
        if before == n {
            continue;
        }
        let total = |c: &Counts| c.iter().map(|e| e.1 as u64).sum::<u64>();
        let closed = total(&n) < total(&before);
        let Ok(fs) = file.fs() else {
            held.remove(&file);
            continue;
        };
        let told = fs.lock().and_then(|mut t| {
            let object = t.data(file.ino)?;
            if closed {
                t.drop_record_locks(file.ino, me)?;
            }
            let gone = t.hold(file.ino, me, &n)?;
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
        if n.is_empty() {
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
/// mapped if this process holds the file, by `mapped` if the call that
/// wrote it mapped it.
pub fn made_data(file: File, object: u64, mapped: Option<super::data::Mapped>) {
    let mut held = HELD.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(e) = held.get_mut(&file)
        && e.1 == 0
    {
        super::data::keep_mapped(object, mapped);
        e.1 = object;
    }
}

/// The host pid of a message's holding: its start is the message's token.
const IN_FLIGHT: i32 = 0;

/// Whether holder `p` (a process, or a message: [`IN_FLIGHT`]) is still
/// there.
pub(super) fn alive(p: (i32, u64)) -> bool {
    p.0 == IN_FLIGHT || crate::procreg::alive(p)
}

/// This process is ending: it holds none of its files any more, nor their
/// locks (its descriptions' go too where no other process holds them).
pub fn exiting() {
    if !ANY.load(Ordering::Relaxed) {
        return;
    }
    let me = crate::sysvipc::me();
    let held = std::mem::take(&mut *HELD.lock().unwrap_or_else(|e| e.into_inner()));
    for (file, (_, kept)) in held {
        if let Ok(fs) = file.fs()
            && let Ok(mut t) = fs.lock()
        {
            let _ = t.drop_record_locks(file.ino, me);
            if let Ok(gone) = t.hold(file.ino, me, &[])
                && let Some(o) = gone.data
            {
                super::data::remove(o);
            }
        }
        super::data::let_go(kept);
    }
}

/// Forget the holders of `fs`'s files with no names that have ended: the
/// files only they held go.
pub fn sweep(fs: &Fs) {
    let Ok(mut t) = fs.lock() else { return };
    for ino in t.unnamed() {
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
    let held: Vec<(File, Counts)> = HELD
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .map(|(f, e)| (*f, e.0.clone()))
        .collect();
    for (file, n) in held {
        if let Ok(fs) = file.fs()
            && let Ok(mut t) = fs.lock()
        {
            let _ = t.hold_unless_counted(file.ino, p, &n);
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
        e.bool(desc.path);
    }
    let p = PLACES.lock().unwrap_or_else(|e| e.into_inner());
    e.u64(p.len() as u64);
    for (&k, (dir, name)) in p.iter() {
        e.u32(k);
        e.u64(*dir);
        e.bytes(name);
    }
    let h = HELD.lock().unwrap_or_else(|e| e.into_inner());
    e.u64(h.len() as u64);
    for (f, (n, _)) in h.iter() {
        e.u64(f.fs);
        e.u64(f.ino);
        e.u64(n.len() as u64);
        for &(id, c) in n {
            e.u64(id);
            e.u32(c);
        }
    }
}

/// What [`save`] wrote, in the new process (which maps no data yet).
pub(crate) fn load(d: &mut Dec) {
    ANY.store(d.bool(), Ordering::Relaxed);
    NEXT_KEY.store(d.u32(), Ordering::Relaxed);
    let n = d.count(29);
    let mut descs = DESCS.lock().unwrap_or_else(|e| e.into_inner());
    for _ in 0..n {
        let k = d.u32();
        let file = File { fs: d.u64(), ino: d.u64() };
        let (id, path) = (d.u64(), d.bool());
        descs.insert(k, Desc { file, id, path });
    }
    let n = d.count(20);
    let mut places = PLACES.lock().unwrap_or_else(|e| e.into_inner());
    for _ in 0..n {
        let k = d.u32();
        let dir = d.u64();
        places.insert(k, (dir, d.bytes()));
    }
    let n = d.count(24);
    let mut held = HELD.lock().unwrap_or_else(|e| e.into_inner());
    for _ in 0..n {
        let file = File { fs: d.u64(), ino: d.u64() };
        let m = d.count(12);
        let counts = (0..m).map(|_| (d.u64(), d.u32())).collect();
        held.insert(file, (counts, 0));
    }
}

/// What a descriptor of the store takes to another process: its file and
/// description, and the token of the message's holding of the file.
#[cfg(not(target_os = "linux"))]
pub(crate) fn export(fd: i32) -> Option<crate::scm::Export> {
    let k = key_of(fd)?;
    let d = descs(|m| m.get(&k).copied())?;
    let token = crate::shared::unique();
    let held =
        d.file.fs().and_then(|fs| fs.lock()?.hold(d.file.ino, (IN_FLIGHT, token), &[(d.id, 1)]));
    if held.is_err() {
        return None;
    }
    let mut e = Enc::default();
    e.u64(d.file.fs);
    e.u64(d.file.ino);
    e.u64(d.id);
    e.bool(d.path);
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
    let (id, path, token) = (d.u64(), d.bool(), d.u64());
    let Ok(fs) = file.fs() else { return false };
    adopt(fd, file, id, path);
    sync(&[]);
    let_go_in_flight(&fs, file.ino, token);
    true
}

/// A message that held `ino` of `fs` as `token` (an [`export`]'s) was taken
/// or never sent.
#[cfg(not(target_os = "linux"))]
fn let_go_in_flight(fs: &Fs, ino: Ino, token: u64) {
    if let Ok(mut t) = fs.lock()
        && let Ok(gone) = t.hold(ino, (IN_FLIGHT, token), &[])
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
    let (_, _, token) = (d.u64(), d.bool(), d.u64());
    if let Ok(fs) = file.fs() {
        let_go_in_flight(&fs, file.ino, token);
    }
}
