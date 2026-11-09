//! The guest's mappings as Linux lists them in `/proc/self/maps` and
//! `/proc/self/smaps`: what each range maps (a file at an offset, the
//! heap, the stack, anonymous memory), with the protections and sharing
//! the guest asked for and whether it is locked.
//!
//! The kernel records each memory system call that succeeds, whichever
//! backend carried it out, and the backends record what they map at load
//! (the program, its dynamic linker and the stack). The host's protections
//! can differ from the guest's — memory the guest maps writable and
//! executable is one or the other at a time on macOS — so the record keeps
//! the guest's. Memory fwe maps for the guest that the guest did not ask
//! for (the native backend's code stubs, a stack's guard page) is listed
//! as anonymous memory with the host's protections, so a program looking
//! for free address space in the list does not pick it.
//!
//! Each process publishes its record after every change, in a shared file
//! beside its process record ([`publish`]), which another process reads
//! for `/proc/<pid>/maps` ([`of_process`]). A fork child, until its first
//! change, is described by what it inherited, kept in its process record
//! ([`forked`]), so a fork makes no file.

use crate::vmas::{Mapping, Piece, Vmas};
use fwe_abi::mman;
use std::os::unix::ffi::OsStrExt;
use std::sync::{Arc, Mutex, MutexGuard};

/// What a mapping is named by in the listing.
#[derive(Debug, Clone, PartialEq)]
pub enum Name {
    Anonymous,
    Heap,
    Stack,
    /// The program, by the path `/proc/self/exe` gives.
    Exe,
    /// A file or another object by its path (`/memfd:x (deleted)`,
    /// `/SYSV0000002a (deleted)`).
    Path(Arc<[u8]>),
}

/// The object a mapping maps and where in it.
#[derive(Debug, Clone, PartialEq)]
pub struct Object {
    pub name: Name,
    /// Linux's device number and inode of the file.
    pub dev: u64,
    pub ino: u64,
    /// The offset into it of the mapping's start, in bytes.
    pub offset: u64,
}

impl Object {
    /// A file mapped from `offset`, named `path`, whose metadata is `st`.
    pub fn file(path: Vec<u8>, st: &fwe_abi::Stat, offset: u64) -> Object {
        Object { name: Name::Path(path.into()), dev: st.st_dev, ino: st.st_ino, offset }
    }
}

/// One mapping.
#[derive(Debug, Clone, PartialEq)]
pub struct Area {
    /// Linux `PROT_READ`, `PROT_WRITE` and `PROT_EXEC` bits.
    pub prot: u64,
    pub shared: bool,
    pub locked: bool,
    /// It maps a file of a `noexec` mount, so it may not be made
    /// executable (Linux's `VM_MAYEXEC` clear).
    pub noexec: bool,
    /// A shared mapping of a file not open for writing, so it may not be
    /// made writable (Linux's `VM_MAYWRITE` clear).
    pub nowrite: bool,
    /// Sealed (`mseal`): not to be unmapped, moved, remapped over, have
    /// its protections changed or, read-only and anonymous, be discarded.
    pub sealed: bool,
    /// What it maps; anonymous memory has offset 0 throughout.
    pub object: Object,
}

impl Mapping for Area {
    fn at(&self, offset: u64) -> Self {
        let mut a = self.clone();
        if matches!(a.object.name, Name::Exe | Name::Path(_)) {
            a.object.offset += offset;
        }
        a
    }
}

impl Area {
    /// The offset into its file of the mapping's start (0 for anonymous
    /// memory).
    pub fn file_offset(&self) -> u64 {
        match self.object.name {
            Name::Exe | Name::Path(_) => self.object.offset,
            _ => 0,
        }
    }

    fn anonymous(prot: u64, name: Name) -> Area {
        Area {
            prot,
            shared: false,
            locked: false,
            noexec: false,
            nowrite: false,
            sealed: false,
            object: Object { name, dev: 0, ino: 0, offset: 0 },
        }
    }
}

/// A process's mappings.
#[derive(Clone)]
pub struct Record {
    areas: Vmas<Area>,
    /// The break's reservation, `[start, limit)`: address space the heap
    /// grows into, not a mapping.
    brk: (u64, u64),
    /// `mlockall(MCL_FUTURE)`: new mappings are locked.
    lock_future: bool,
    /// The program's path, as `/proc/self/exe` names it, and its file's
    /// device and inode.
    exe: Vec<u8>,
    exe_id: (u64, u64),
}

impl Default for Record {
    fn default() -> Self {
        Record::new()
    }
}

impl Record {
    pub const fn new() -> Record {
        Record {
            areas: Vmas::new(),
            brk: (0, 0),
            lock_future: false,
            exe: Vec::new(),
            exe_id: (0, 0),
        }
    }

    /// The program is `path`, whose file's device and inode are `id`.
    pub fn set_exe(&mut self, path: Vec<u8>, id: (u64, u64)) {
        self.exe = path;
        self.exe_id = id;
    }

    /// The program, as the listing names it.
    pub fn exe(&self) -> Exe<'_> {
        Exe { path: &self.exe, id: self.exe_id }
    }

    /// The record in a form [`Record::decode`] reads back.
    pub fn encode(&self, e: &mut crate::snapshot::Enc) {
        e.u64(self.brk.0);
        e.u64(self.brk.1);
        e.bool(self.lock_future);
        e.bytes(&self.exe);
        e.u64(self.exe_id.0);
        e.u64(self.exe_id.1);
        let all: Vec<_> = self.areas.iter().collect();
        e.u64(all.len() as u64);
        for p in all {
            let a = p.value;
            for v in [p.start, p.end, a.prot, a.object.dev, a.object.ino, a.object.offset] {
                e.u64(v);
            }
            e.bool(a.shared);
            e.bool(a.locked);
            e.bool(a.noexec);
            e.bool(a.nowrite);
            e.bool(a.sealed);
            match &a.object.name {
                Name::Anonymous => e.u8(0),
                Name::Heap => e.u8(1),
                Name::Stack => e.u8(2),
                Name::Exe => e.u8(3),
                Name::Path(p) => {
                    e.u8(4);
                    e.bytes(p);
                }
            }
        }
    }

    /// The record [`Record::encode`] wrote.
    pub fn decode(d: &mut crate::snapshot::Dec) -> Record {
        let mut r = Record::new();
        r.brk = (d.u64(), d.u64());
        r.lock_future = d.bool();
        r.exe = d.bytes();
        r.exe_id = (d.u64(), d.u64());
        let n = d.count(8 * 6 + 6);
        for _ in 0..n {
            let (start, end, prot, dev, ino, offset) =
                (d.u64(), d.u64(), d.u64(), d.u64(), d.u64(), d.u64());
            let (shared, locked, noexec, nowrite, sealed) =
                (d.bool(), d.bool(), d.bool(), d.bool(), d.bool());
            let name = match d.u8() {
                1 => Name::Heap,
                2 => Name::Stack,
                3 => Name::Exe,
                4 => Name::Path(d.bytes().into()),
                _ => Name::Anonymous,
            };
            let object = Object { name, dev, ino, offset };
            let area = Area { prot, shared, locked, noexec, nowrite, sealed, object };
            r.areas.insert(start, end, area);
        }
        r
    }

    /// The guest mapped `[start, start + len)` with Linux protections
    /// `prot`, shared or private, of `object` (anonymous memory if
    /// `None`). Returns whether the new mapping is locked
    /// (`mlockall(MCL_FUTURE)` was called).
    pub fn mapped(
        &mut self,
        start: u64,
        len: u64,
        prot: u64,
        shared: bool,
        object: Option<Object>,
    ) -> bool {
        let locked = self.lock_future;
        let object = object.unwrap_or(Object { name: Name::Anonymous, dev: 0, ino: 0, offset: 0 });
        let area =
            Area { prot, shared, locked, noexec: false, nowrite: false, sealed: false, object };
        self.areas.insert(start, start + len, area);
        locked
    }

    /// Name the mapping `[start, start + len)` as what it maps (a System V
    /// segment, whose file is fwe's).
    pub fn rename(&mut self, start: u64, len: u64, object: Object) {
        self.areas.update(start, start + len, |a| Area { object: object.clone(), ..a.clone() });
    }

    /// Seal `[start, end)` (`mseal`): every page of it mapped, else
    /// `ENOMEM`.
    pub fn seal(&mut self, start: u64, end: u64) -> Result<(), i32> {
        let mut at = start;
        for p in self.areas.iter().filter(|p| p.end > start && p.start < end) {
            if p.start > at {
                return Err(fwe_abi::errno::ENOMEM);
            }
            at = p.end;
        }
        if at < end {
            return Err(fwe_abi::errno::ENOMEM);
        }
        self.areas.update(start, end, |a| Area { sealed: true, ..a.clone() });
        Ok(())
    }

    /// Whether any of `[start, end)` is sealed.
    pub fn any_sealed(&self, start: u64, end: u64) -> bool {
        self.areas.iter().any(|p| p.end > start && p.start < end && p.value.sealed)
    }

    /// Whether any of `[start, end)` is sealed, private, anonymous and not
    /// writable: memory `madvise` may not discard.
    pub fn any_sealed_read_only(&self, start: u64, end: u64) -> bool {
        self.areas.iter().any(|p| {
            let a = p.value;
            p.end > start
                && p.start < end
                && a.sealed
                && !a.shared
                && !matches!(a.object.name, Name::Exe | Name::Path(_))
                && a.prot & fwe_abi::mman::PROT_WRITE == 0
        })
    }

    /// The guest unmapped `[start, start + len)`.
    pub fn unmapped(&mut self, start: u64, len: u64) {
        self.areas.remove(start, start + len);
    }

    /// The guest changed the protections of `[start, start + len)` to
    /// `prot`.
    /// The mapping `[start, start + len)` is of a file of a `noexec` mount.
    pub fn no_exec(&mut self, start: u64, len: u64) {
        self.areas.update(start, start + len, |a| Area { noexec: true, ..a.clone() });
    }

    /// The mapping `[start, start + len)` shares a file not open for
    /// writing.
    pub fn no_write(&mut self, start: u64, len: u64) {
        self.areas.update(start, start + len, |a| Area { nowrite: true, ..a.clone() });
    }

    /// Whether any of `[start, start + len)` may not be made writable.
    pub fn any_nowrite(&self, start: u64, len: u64) -> bool {
        self.areas.pieces(start, start + len).iter().any(|p| p.value.nowrite)
    }

    /// Whether any of `[start, start + len)` maps a file of a `noexec`
    /// mount.
    pub fn any_noexec(&self, start: u64, len: u64) -> bool {
        self.areas.pieces(start, start + len).iter().any(|p| p.value.noexec)
    }

    pub fn protected(&mut self, start: u64, len: u64, prot: u64) {
        self.areas.update(start, start + len, |a| Area { prot, ..a.clone() });
    }

    /// `mremap` moved or resized `[old, old + old_len)` to `[new, new +
    /// new_len)`: what was there moves, a grown part continues its last
    /// mapping, a shrunk tail goes.
    pub fn remapped(&mut self, old: u64, old_len: u64, new: u64, new_len: u64) {
        let pieces = self.areas.remove(old, old + old_len);
        let keep = new_len.min(old_len);
        let mut last: Option<Piece<Area>> = None;
        for p in pieces {
            if p.start >= old + keep {
                break;
            }
            let end = p.end.min(old + keep);
            self.areas.insert(new + (p.start - old), new + (end - old), p.value.clone());
            last = Some(Piece { start: p.start, end, value: p.value });
        }
        if new_len > old_len
            && let Some(l) = last
        {
            let grown = l.value.at(l.end - l.start);
            self.areas.insert(new + old_len, new + new_len, grown);
        }
    }

    /// The heap is `[start, end)` of the break's reservation `[start,
    /// limit)`.
    pub fn set_heap(&mut self, start: u64, end: u64, limit: u64) {
        self.brk = (start, limit);
        let heap: Vec<(u64, u64)> = self
            .areas
            .pieces(start, limit)
            .into_iter()
            .filter(|p| p.value.object.name == Name::Heap)
            .map(|p| (p.start, p.end))
            .collect();
        for (a, b) in heap {
            self.areas.remove(a, b);
        }
        if end > start {
            let mut heap = Area::anonymous(mman::PROT_READ | mman::PROT_WRITE, Name::Heap);
            heap.locked = self.lock_future;
            self.areas.insert(start, end, heap);
        }
    }

    /// The main thread's stack is `[start, end)`.
    pub fn set_stack(&mut self, start: u64, end: u64) {
        let rw = mman::PROT_READ | mman::PROT_WRITE;
        self.areas.insert(start, end, Area::anonymous(rw, Name::Stack));
    }

    /// An ELF image `elf` was loaded `bias` bytes from its addresses, for
    /// pages of `page` bytes: each segment maps the file `name` (whose
    /// device and inode are `id`) as far as the file has its contents, and
    /// anonymous memory (zeroed) beyond, as Linux's loader maps it.
    pub fn loaded(
        &mut self,
        elf: &fwe_elf::Elf<'_>,
        bias: u64,
        page: u64,
        name: Name,
        id: (u64, u64),
    ) {
        let up = |a: u64| (a + page - 1) & !(page - 1);
        for ph in elf.loads() {
            let mut prot = 0;
            for (on, bit) in [
                (ph.readable(), mman::PROT_READ),
                (ph.writable(), mman::PROT_WRITE),
                (ph.executable(), mman::PROT_EXEC),
            ] {
                if on {
                    prot |= bit;
                }
            }
            let start = (ph.vaddr + bias) & !(page - 1);
            let file_end = up(ph.vaddr + bias + ph.filesz);
            let end = up(ph.vaddr + bias + ph.memsz).max(file_end);
            let object = Object {
                name: name.clone(),
                dev: id.0,
                ino: id.1,
                offset: ph.offset.saturating_sub(ph.vaddr + bias - start),
            };
            if file_end > start {
                let area = Area {
                    prot,
                    shared: false,
                    locked: false,
                    noexec: false,
                    nowrite: false,
                    sealed: false,
                    object,
                };
                self.areas.insert(start, file_end, area);
            }
            if end > file_end {
                self.areas.insert(file_end, end, Area::anonymous(prot, Name::Anonymous));
            }
        }
    }

    /// Lock (`mlock`) or unlock `[start, start + len)`.
    pub fn lock(&mut self, start: u64, len: u64, on: bool) {
        self.areas.update(start, start + len, |a| Area { locked: on, ..a.clone() });
    }

    /// `mlockall`: lock every mapping (`current`), and those made from now
    /// on (`future`); `munlockall` (`None`): unlock all.
    pub fn lock_all(&mut self, how: Option<(bool, bool)>) {
        let (current, future) = how.unwrap_or((false, false));
        if current || how.is_none() {
            let on = how.is_some();
            self.areas.update(0, u64::MAX, |a| Area { locked: on, ..a.clone() });
        }
        self.lock_future = future;
    }

    /// How many bytes of the mappings are locked.
    pub fn locked_bytes(&self) -> u64 {
        self.areas.iter().filter(|p| p.value.locked).map(|p| p.end - p.start).sum()
    }

    /// How many bytes of `[start, end)` are locked.
    pub fn locked_in(&self, start: u64, end: u64) -> u64 {
        let pieces = self.areas.pieces(start, end);
        pieces.iter().filter(|p| p.value.locked).map(|p| p.end - p.start).sum()
    }

    /// How many bytes are mapped.
    pub fn total_bytes(&self) -> u64 {
        self.areas.iter().map(|p| p.end - p.start).sum()
    }

    /// The mappings, cut to `[start, end)`.
    pub fn areas_in(&self, start: u64, end: u64) -> Vec<Piece<Area>> {
        self.areas.pieces(start, end)
    }

    /// Every mapping, in address order.
    pub fn areas(&self) -> Vec<Piece<Area>> {
        self.areas
            .iter()
            .map(|p| Piece { start: p.start, end: p.end, value: p.value.clone() })
            .collect()
    }

    /// The mappings with `extra` — memory fwe mapped for the guest that the
    /// record does not have, as `(start, end, Linux prot)` — added where
    /// nothing is recorded, as anonymous memory, outside the break's
    /// reservation.
    pub fn with_extra(&self, extra: &[(u64, u64, u64)]) -> Vec<Piece<Area>> {
        let (brk_lo, brk_hi) = self.brk;
        let mut v = self.areas.clone();
        for &(start, end, prot) in extra {
            // Each gap the record leaves in the range, less the reservation.
            let mut gaps = Vec::new();
            let mut at = start;
            for p in v.pieces(start, end) {
                if p.start > at {
                    gaps.push((at, p.start));
                }
                at = p.end;
            }
            if at < end {
                gaps.push((at, end));
            }
            for (a, b) in gaps {
                for (lo, hi) in [(a, b.min(brk_lo)), (a.max(brk_hi), b)] {
                    if lo < hi {
                        v.insert(lo, hi, Area::anonymous(prot, Name::Anonymous));
                    }
                }
            }
        }
        v.iter().map(|p| Piece { start: p.start, end: p.end, value: p.value.clone() }).collect()
    }
}

/// The guest's page size, for `smaps`.
static PAGE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(4096);

/// The guest's pages are `page` bytes.
pub fn set_page_size(page: u64) {
    PAGE.store(page, std::sync::atomic::Ordering::Relaxed);
}

/// The guest's page size.
pub fn page_size() -> u64 {
    PAGE.load(std::sync::atomic::Ordering::Relaxed)
}

/// This process's record.
static RECORD: Mutex<Record> = Mutex::new(Record::new());

/// This process's record, to read or change.
pub fn record() -> MutexGuard<'static, Record> {
    RECORD.lock().unwrap_or_else(|e| e.into_inner())
}

/// Forget every mapping (the old program's, at `execve`).
pub fn clear() {
    *record() = Record::new();
}

/// Run `f` holding the record's lock (see [`crate::fork_locked`]).
pub(crate) fn hold<R>(f: impl FnOnce() -> R) -> R {
    let _g = record();
    f()
}

/// Save the record for a fork child that is a fresh process.
pub fn save(e: &mut crate::snapshot::Enc) {
    record().encode(e);
}

/// The record [`save`] saved.
pub fn restore(d: &mut crate::snapshot::Dec) {
    *record() = Record::decode(d);
}

/// A process's mappings as it published them for other processes
/// ([`publish`]).
pub struct Published {
    pub record: Record,
    /// Its page size.
    pub page: u64,
    /// The memory fwe mapped for the guest, host `(start, len)` (see
    /// [`crate::mm::tracked`]).
    pub tracked: Vec<(u64, u64)>,
    /// Its guest addresses backed elsewhere, `(guest, len, host)` (see
    /// [`crate::uaccess::translations`]).
    pub translations: Vec<(u64, u64, u64)>,
}

impl Published {
    /// The host address of guest address `addr` in that process.
    pub fn host_of(&self, addr: u64) -> u64 {
        self.translations
            .iter()
            .find(|&&(g, l, _)| addr >= g && addr < g + l)
            .map_or(addr, |&(g, _, h)| h + (addr - g))
    }
}

/// The shared file this process publishes its mappings in: other
/// processes read it for `/proc/<pid>/maps`. It holds a sequence word
/// (odd while a change is written), the length of what follows, and the
/// encoded [`Published`].
struct Outbox {
    pid: i32,
    fd: i32,
    map: *mut u8,
    cap: usize,
}

// SAFETY: the mapping is this process's own, used under `OUTBOX`'s lock.
unsafe impl Send for Outbox {}

static OUTBOX: Mutex<Option<Outbox>> = Mutex::new(None);

/// The header before the encoded record: the sequence word and the length.
const HEADER: usize = 16;

/// This process's mappings encoded as [`publish`] publishes them.
pub fn snapshot() -> Vec<u8> {
    // The host's view first: its lock comes before the record's.
    let tracked = crate::mm::tracked();
    let translations = crate::uaccess::translations();
    let mut e = crate::snapshot::Enc::new();
    record().encode(&mut e);
    e.u64(page_size());
    e.u64(tracked.len() as u64);
    for (start, len) in tracked {
        e.u64(start);
        e.u64(len);
    }
    e.u64(translations.len() as u64);
    for (g, l, h) in translations {
        for v in [g, l, h] {
            e.u64(v);
        }
    }
    e.into_bytes()
}

/// Let go of the parent's file a fork child inherited.
fn drop_inherited(out: &mut Option<Outbox>) {
    // SAFETY: getpid cannot fail.
    let me = unsafe { libc::getpid() };
    if let Some(o) = out.as_ref()
        && o.pid != me
    {
        // SAFETY: the mapping and descriptor are this process's copies.
        unsafe {
            libc::munmap(o.map.cast(), o.cap);
            libc::close(o.fd);
        }
        *out = None;
    }
}

/// In a fork child: its mappings, which are its parent's, for the record
/// it writes as it starts (see [`crate::procreg::own_line`]). It makes a
/// file of its own only once they change, so a fork costs no file.
pub fn forked() -> Vec<u8> {
    drop_inherited(&mut OUTBOX.lock().unwrap_or_else(|e| e.into_inner()));
    snapshot()
}

/// Publish this process's mappings for other processes to read (after
/// each change, and in a new program).
pub fn publish() {
    let body = snapshot();
    let mut out = OUTBOX.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: getpid cannot fail.
    let me = unsafe { libc::getpid() };
    drop_inherited(&mut out);
    if out.is_none() {
        let Some(path) = crate::procreg::maps_path(me) else { return };
        let Ok(c) = std::ffi::CString::new(path) else { return };
        // SAFETY: a NUL-terminated path in fwe's private directory.
        let fd = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return;
        }
        let Ok(fd) = crate::fdtable::reserve(fd) else { return };
        *out = Some(Outbox { pid: me, fd, map: std::ptr::null_mut(), cap: 0 });
    }
    let Some(o) = out.as_mut() else { return };
    let need = HEADER + body.len();
    if need > o.cap {
        let cap = need.next_power_of_two().max(1 << 16);
        // SAFETY: fwe's own file; growing it keeps what it holds.
        if unsafe { libc::ftruncate(o.fd, cap as libc::off_t) } != 0 {
            return;
        }
        // SAFETY: a fresh shared mapping of the whole file.
        let map = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                cap,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                o.fd,
                0,
            )
        };
        if map == libc::MAP_FAILED {
            return;
        }
        if !o.map.is_null() {
            // SAFETY: the old mapping, replaced by the new one.
            unsafe { libc::munmap(o.map.cast(), o.cap) };
        }
        o.map = map.cast();
        o.cap = cap;
    }
    use std::sync::atomic::{AtomicU64, Ordering, fence};
    // SAFETY: the mapping is `cap` bytes, at least `need`, page-aligned
    // (so the words are aligned), and only this process writes it.
    unsafe {
        let seq = &*(o.map as *const AtomicU64);
        let len = &*(o.map.add(8) as *const AtomicU64);
        let s = seq.load(Ordering::Relaxed);
        seq.store(s | 1, Ordering::Relaxed);
        fence(Ordering::SeqCst);
        std::ptr::copy_nonoverlapping(body.as_ptr(), o.map.add(HEADER), body.len());
        len.store(body.len() as u64, Ordering::Relaxed);
        fence(Ordering::SeqCst);
        seq.store((s | 1) + 1, Ordering::Release);
    }
}

/// What [`snapshot`] encoded.
fn decode_published(body: &[u8]) -> Option<Published> {
    let mut d = crate::snapshot::Dec::new(body);
    let record = Record::decode(&mut d);
    let page = d.u64();
    let n = d.count(16);
    let tracked = (0..n).map(|_| (d.u64(), d.u64())).collect();
    let n = d.count(24);
    let translations = (0..n).map(|_| (d.u64(), d.u64(), d.u64())).collect();
    d.finish().ok()?;
    Some(Published { record, page, tracked, translations })
}

/// The mappings host process `pid` published, if it is a process of
/// fwe's that has.
pub fn of_process(pid: i32) -> Option<Published> {
    use std::os::unix::fs::FileExt;
    let path = crate::procreg::maps_path(pid)?;
    let Ok(file) = std::fs::File::open(std::ffi::OsStr::from_bytes(&path)) else {
        // None published yet: what it was forked with.
        let r = crate::procreg::read(pid)?;
        return (!r.maps.is_empty()).then(|| decode_published(&r.maps)).flatten();
    };
    let word = |at: u64| -> Option<u64> {
        let mut b = [0u8; 8];
        file.read_exact_at(&mut b, at).ok()?;
        Some(u64::from_ne_bytes(b))
    };
    // A consistent copy: the same even sequence word before and after.
    for _ in 0..1000 {
        let before = word(0)?;
        if before & 1 == 0 {
            let len = word(8)? as usize;
            let mut body = vec![0u8; len];
            if file.read_exact_at(&mut body, HEADER as u64).is_ok() && word(0)? == before {
                return decode_published(&body);
            }
        }
        std::thread::yield_now();
    }
    None
}

/// What the listing shows of each mapping beyond its line (`smaps`).
pub struct Usage {
    /// Bytes of it in memory.
    pub resident: u64,
}

/// The program, as the listing names it: its path and its file's device
/// and inode.
pub struct Exe<'a> {
    pub path: &'a [u8],
    pub id: (u64, u64),
}

/// One `/proc/self/maps` line for mapping `[start, end)`.
fn line(start: u64, end: u64, a: &Area, exe: &Exe<'_>) -> Vec<u8> {
    let (name, (dev, ino)) = name_of(a, exe);
    let flag = |bit: u64, c: char| if a.prot & bit != 0 { c } else { '-' };
    let mut out = format!(
        "{start:08x}-{end:08x} {}{}{}{} {:08x} {:02x}:{:02x} {ino} ",
        flag(mman::PROT_READ, 'r'),
        flag(mman::PROT_WRITE, 'w'),
        flag(mman::PROT_EXEC, 'x'),
        if a.shared { 's' } else { 'p' },
        a.file_offset(),
        crate::devnodes::major(dev),
        crate::devnodes::minor(dev),
    )
    .into_bytes();
    if !name.is_empty() {
        // Linux pads the line to 72 columns and a space before the name.
        out.resize(out.len().max(72), b' ');
        out.push(b' ');
        out.extend_from_slice(name);
    }
    out.push(b'\n');
    out
}

/// The `smaps` fields after a mapping's line.
fn details(start: u64, end: u64, a: &Area, page: u64, usage: &Usage) -> Vec<u8> {
    let kb = |b: u64| b >> 10;
    let anonymous = matches!(a.object.name, Name::Anonymous | Name::Heap | Name::Stack);
    let rss = usage.resident;
    let (shared, private) = if a.shared { (rss, 0) } else { (0, rss) };
    let mut out = String::new();
    let mut field = |name: &str, v: u64| {
        out.push_str(&format!("{:<16}{:>8} kB\n", format!("{name}:"), v));
    };
    field("Size", kb(end - start));
    field("KernelPageSize", kb(page));
    field("MMUPageSize", kb(page));
    field("Rss", kb(rss));
    field("Pss", kb(rss));
    field("Pss_Dirty", kb(if anonymous { rss } else { 0 }));
    field("Shared_Clean", 0);
    field("Shared_Dirty", kb(shared));
    field("Private_Clean", 0);
    field("Private_Dirty", kb(private));
    field("Referenced", kb(rss));
    field("Anonymous", kb(if anonymous && !a.shared { rss } else { 0 }));
    field("KSM", 0);
    field("LazyFree", 0);
    field("AnonHugePages", 0);
    field("ShmemPmdMapped", 0);
    field("FilePmdMapped", 0);
    field("Shared_Hugetlb", 0);
    field("Private_Hugetlb", 0);
    field("Swap", 0);
    field("SwapPss", 0);
    field("Locked", kb(if a.locked { rss } else { 0 }));
    out.push_str("THPeligible:    0\n");
    let mut flags = String::from("VmFlags:");
    for (on, f) in [
        (a.prot & mman::PROT_READ != 0, "rd"),
        (a.prot & mman::PROT_WRITE != 0, "wr"),
        (a.prot & mman::PROT_EXEC != 0, "ex"),
        (a.shared, "sh"),
        (true, "mr"),
        (true, "mw"),
        (true, "me"),
        (a.shared, "ms"),
        (a.object.name == Name::Stack, "gd"),
        (a.locked, "lo"),
        (anonymous, "ac"),
    ] {
        if on {
            flags.push(' ');
            flags.push_str(f);
        }
    }
    out.push_str(&flags);
    out.push_str(" \n");
    out.into_bytes()
}

/// The listing of `areas` (`/proc/self/maps`; with `smaps`, `usage` gives
/// each one's details for `/proc/self/smaps`).
pub fn render(
    areas: &[Piece<Area>],
    exe: &Exe<'_>,
    page: u64,
    smaps: Option<&dyn Fn(u64, u64) -> Usage>,
) -> Vec<u8> {
    let mut out = Vec::new();
    for p in areas {
        out.extend(line(p.start, p.end, &p.value, exe));
        if let Some(usage) = smaps {
            out.extend(details(p.start, p.end, &p.value, page, &usage(p.start, p.end)));
        }
    }
    out
}

/// The mapping a `PROCMAP_QUERY` with `flags` asks about at `addr`, of
/// `areas`: the one containing it, or with `COVERING_OR_NEXT_VMA` the first
/// at or above it, of those with the protections, sharing and file backing
/// the flags ask for.
pub fn query(areas: &[Piece<Area>], addr: u64, flags: u64) -> Option<&Piece<Area>> {
    use fwe_abi::procmap::*;
    let wanted = |p: &&Piece<Area>| {
        let a = &p.value;
        (flags & VMA_READABLE == 0 || a.prot & mman::PROT_READ != 0)
            && (flags & VMA_WRITABLE == 0 || a.prot & mman::PROT_WRITE != 0)
            && (flags & VMA_EXECUTABLE == 0 || a.prot & mman::PROT_EXEC != 0)
            && (flags & VMA_SHARED == 0 || a.shared)
            && (flags & FILE_BACKED_VMA == 0 || matches!(a.object.name, Name::Exe | Name::Path(_)))
    };
    if flags & COVERING_OR_NEXT_VMA != 0 {
        areas.iter().filter(|p| p.end > addr).find(wanted)
    } else {
        areas.iter().find(|p| p.start <= addr && addr < p.end).filter(wanted)
    }
}

/// What the listing names mapping `a` (empty for plain anonymous memory),
/// and its file's device and inode.
pub fn name_of<'a>(a: &'a Area, exe: &Exe<'a>) -> (&'a [u8], (u64, u64)) {
    match &a.object.name {
        Name::Anonymous => (b"", (0, 0)),
        Name::Heap => (b"[heap]", (0, 0)),
        Name::Stack => (b"[stack]", (0, 0)),
        Name::Exe => (exe.path, exe.id),
        Name::Path(p) => (p, (a.object.dev, a.object.ino)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, offset: u64) -> Option<Object> {
        Some(Object { name: Name::Path(path.as_bytes().into()), dev: 0x803, ino: 42, offset })
    }

    #[test]
    fn listing_follows_the_calls() {
        let mut r = Record::new();
        let ro = mman::PROT_READ;
        let rw = mman::PROT_READ | mman::PROT_WRITE;
        r.mapped(0x10000, 0x4000, ro | mman::PROT_EXEC, false, file("/lib/a.so", 0));
        r.mapped(0x14000, 0x4000, ro, false, file("/lib/a.so", 0x4000));
        r.mapped(0x20000, 0x8000, rw, true, None);
        r.set_heap(0x40000, 0x48000, 0x80000);
        r.set_stack(0x7f000, 0x80000);
        r.protected(0x24000, 0x4000, ro);
        let text = String::from_utf8(render(
            &r.areas(),
            &Exe { path: b"/bin/x", id: (0, 0) },
            0x4000,
            None,
        ))
        .unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 6, "{text}");
        assert!(lines[0].starts_with("00010000-00014000 r-xp 00000000 08:03 42 "), "{text}");
        assert!(lines[0].ends_with(" /lib/a.so") && lines[0].find('/') == Some(73), "{text}");
        assert!(lines[1].starts_with("00014000-00018000 r--p 00004000 08:03 42 "), "{text}");
        assert_eq!(lines[2], "00020000-00024000 rw-s 00000000 00:00 0 ");
        assert_eq!(lines[3], "00024000-00028000 r--s 00000000 00:00 0 ");
        assert!(lines[4].starts_with("00040000-00048000 rw-p") && lines[4].ends_with("[heap]"));
        assert!(lines[5].ends_with("[stack]"));
        // The heap shrinks; a part of the file mapping goes; a mapping
        // grows by moving.
        r.set_heap(0x40000, 0x44000, 0x80000);
        r.unmapped(0x12000, 0x4000);
        r.remapped(0x20000, 0x8000, 0x100000, 0xc000);
        let after: Vec<_> = r.areas().into_iter().map(|p| (p.start, p.end)).collect();
        assert_eq!(
            after,
            vec![
                (0x10000, 0x12000),
                (0x16000, 0x18000),
                (0x40000, 0x44000),
                (0x7f000, 0x80000),
                (0x100000, 0x104000),
                (0x104000, 0x10c000)
            ]
        );
        // The part of the file mapping left past the hole keeps its offset.
        assert_eq!(r.areas_in(0x16000, 0x18000)[0].value.object.offset, 0x6000);
    }

    #[test]
    fn locking_and_extra_memory() {
        let mut r = Record::new();
        let rw = mman::PROT_READ | mman::PROT_WRITE;
        r.mapped(0x10000, 0x8000, rw, false, None);
        r.lock(0x14000, 0x4000, true);
        let usage = |s: u64, e: u64| Usage { resident: e - s };
        let text = String::from_utf8(render(
            &r.areas(),
            &Exe { path: b"", id: (0, 0) },
            0x4000,
            Some(&usage),
        ))
        .unwrap();
        assert!(text.contains("Locked:                0 kB"), "{text}");
        assert!(text.contains("Locked:               16 kB"), "{text}");
        assert!(text.contains(" lo ac \n"), "{text}");
        r.lock_all(Some((false, true)));
        assert!(r.mapped(0x30000, 0x4000, rw, false, None));
        r.lock_all(None);
        assert!(!r.mapped(0x34000, 0x4000, rw, false, None));
        assert!(r.areas().iter().all(|p| !p.value.locked));
        // Memory fwe mapped beside the record's, less the break.
        r.set_heap(0x50000, 0x50000, 0x60000);
        let all = r.with_extra(&[(0x18000, 0x20000, mman::PROT_READ), (0x4c000, 0x64000, 0)]);
        let ranges: Vec<_> = all.iter().map(|p| (p.start, p.end, p.value.prot)).collect();
        assert_eq!(
            ranges,
            vec![
                (0x10000, 0x18000, rw),
                (0x18000, 0x20000, mman::PROT_READ),
                (0x30000, 0x38000, rw),
                (0x4c000, 0x50000, 0),
                (0x60000, 0x64000, 0)
            ]
        );
    }
}
