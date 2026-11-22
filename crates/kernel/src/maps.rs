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
//! for free address space in the list does not pick it. The latest plain
//! anonymous mapping waits beside the list until anything reads it
//! ([`record`]): one unmapped whole before then, as a program's buffer
//! often is, never costs the list a change.
//!
//! Each process publishes its record once it changed, before its next
//! system call that is not a memory call and before a fork, in a shared
//! file beside its process record ([`publish`]), which another process reads
//! for `/proc/<pid>/maps` ([`of_process`]). A fork child, until its first
//! change, is described by what it inherited, kept in its process record
//! ([`forked`]), so a fork makes no file.

use crate::vmas::{Mapping, Piece, Vmas};
use fwe_abi::mman;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};
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
    /// The file itself, where it has no name to be found by.
    pub held: Option<HeldFile>,
}

impl Object {
    /// A file mapped from `offset`, named `path`, whose metadata is `st`.
    pub fn file(path: Vec<u8>, st: &fwe_abi::Stat, offset: u64) -> Object {
        Object { name: Name::Path(path.into()), dev: st.st_dev, ino: st.st_ino, offset, held: None }
    }

    /// Anonymous memory, `name`d.
    fn anonymous(name: Name) -> Object {
        Object { name, dev: 0, ino: 0, offset: 0, held: None }
    }
}

/// A host descriptor of a mapped file with no name (a memfd, a file
/// deleted or made with `O_TMPFILE`), in fwe's reserved range, held while
/// a mapping of it lasts as Linux's mapping holds its file: what grows or
/// remaps the mapping maps more of the file through it (a file with a name
/// is opened again by it). Not carried to a fork child that is a fresh
/// process. Any two of the same file are alike.
#[derive(Debug, Clone)]
pub struct HeldFile(pub Arc<std::os::fd::OwnedFd>);

impl PartialEq for HeldFile {
    fn eq(&self, _: &HeldFile) -> bool {
        true
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
    /// Anonymous memory's name (`PR_SET_VMA_ANON_NAME`), as the listing
    /// shows it (`[anon:name]`).
    pub label: Option<Arc<[u8]>>,
}

impl Mapping for Area {
    fn at(&self, offset: u64) -> Self {
        let mut a = self.clone();
        if matches!(a.object.name, Name::Exe | Name::Path(_)) {
            a.object.offset += offset;
        }
        a
    }

    fn continues(&self, offset: u64, next: &Self) -> bool {
        let (a, b) = (&self.object, &next.object);
        let moved = if matches!(a.name, Name::Exe | Name::Path(_)) { offset } else { 0 };
        self.prot == next.prot
            && self.shared == next.shared
            && self.locked == next.locked
            && self.noexec == next.noexec
            && self.nowrite == next.nowrite
            && self.sealed == next.sealed
            && a.dev == b.dev
            && a.ino == b.ino
            && a.offset.wrapping_add(moved) == b.offset
            && a.name == b.name
            && self.label == next.label
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

    /// Private anonymous memory (the break and the stack too): what
    /// `MADV_DONTNEED` zero-fills, and `MADV_FREE` and `MADV_WIPEONFORK`
    /// take.
    pub fn private_anonymous(&self) -> bool {
        !self.shared && matches!(self.object.name, Name::Anonymous | Name::Heap | Name::Stack)
    }

    fn anonymous(prot: u64, name: Name) -> Area {
        Area {
            prot,
            shared: false,
            locked: false,
            noexec: false,
            nowrite: false,
            sealed: false,
            object: Object::anonymous(name),
            label: None,
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
    /// Some memory was sealed: until then no call looks for a seal.
    any_sealed: bool,
    /// The latest plain mapping (anonymous, unlocked: start, length,
    /// protection, shared), not yet among the areas: one unmapped whole
    /// before anything looks is never put there ([`mapped_plain`],
    /// [`unmapped`]). [`record`] puts it there first.
    pending: Option<(u64, u64, u64, bool)>,
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
            any_sealed: false,
            pending: None,
        }
    }

    /// Put the pending mapping among the areas.
    fn settle(&mut self) {
        if let Some((start, len, prot, shared)) = self.pending.take() {
            self.mapped(start, len, prot, shared, None);
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
        e.u64(self.areas.len() as u64);
        for p in self.areas.iter() {
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
            e.bytes(a.label.as_deref().unwrap_or_default());
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
            let object = Object { name, dev, ino, offset, held: None };
            let label = Some(d.bytes()).filter(|l| !l.is_empty()).map(Into::into);
            let area = Area { prot, shared, locked, noexec, nowrite, sealed, object, label };
            r.any_sealed |= sealed;
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
        let object = object.unwrap_or(Object::anonymous(Name::Anonymous));
        let area = Area {
            prot,
            shared,
            locked,
            noexec: false,
            nowrite: false,
            sealed: false,
            object,
            label: None,
        };
        self.areas.insert(start, start + len, area);
        locked
    }

    /// Name the anonymous memory in `[start, end)` `name` (`None`: no
    /// name), as `PR_SET_VMA_ANON_NAME` does: `EBADF` if a file is mapped
    /// in it (nothing named then), `ENOMEM` past a hole (the rest named).
    pub fn set_anon_name(&mut self, start: u64, end: u64, name: Option<&[u8]>) -> Result<(), i32> {
        let pieces: Vec<_> = self.areas.overlapping(start, end).collect();
        if pieces.iter().any(|p| matches!(p.value.object.name, Name::Exe | Name::Path(_))) {
            return Err(fwe_abi::errno::EBADF);
        }
        let mut at = start;
        let mut hole = false;
        for p in &pieces {
            hole |= p.start > at;
            at = p.end;
        }
        hole |= at < end;
        let label = |shared: bool| -> Option<Arc<[u8]>> {
            let kind: &[u8] = if shared { b"[anon_shmem:" } else { b"[anon:" };
            name.map(|n| [kind, n, b"]"].concat().into())
        };
        self.areas.update(start, end, |a| Area { label: label(a.shared), ..a.clone() });
        if hole { Err(fwe_abi::errno::ENOMEM) } else { Ok(()) }
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
        for p in self.areas.overlapping(start, end) {
            if p.start > at {
                return Err(fwe_abi::errno::ENOMEM);
            }
            at = p.end;
        }
        if at < end {
            return Err(fwe_abi::errno::ENOMEM);
        }
        self.areas.update(start, end, |a| Area { sealed: true, ..a.clone() });
        self.any_sealed = true;
        Ok(())
    }

    /// Whether any of `[start, end)` is sealed.
    pub fn any_sealed(&self, start: u64, end: u64) -> bool {
        self.any_sealed && self.areas.overlapping(start, end).any(|p| p.value.sealed)
    }

    /// Whether any of `[start, end)` is sealed, private, anonymous and not
    /// writable: memory `madvise` may not discard.
    pub fn any_sealed_read_only(&self, start: u64, end: u64) -> bool {
        self.any_sealed
            && self.areas.overlapping(start, end).any(|p| {
                let a = p.value;
                a.sealed
                    && !a.shared
                    && !matches!(a.object.name, Name::Exe | Name::Path(_))
                    && a.prot & fwe_abi::mman::PROT_WRITE == 0
            })
    }

    /// The guest unmapped `[start, start + len)`.
    pub fn unmapped(&mut self, start: u64, len: u64) {
        self.areas.clear(start, start + len);
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
        self.areas.overlapping(start, start + len).any(|p| p.value.nowrite)
    }

    /// Whether any of `[start, start + len)` maps a file of a `noexec`
    /// mount.
    pub fn any_noexec(&self, start: u64, len: u64) -> bool {
        self.areas.overlapping(start, start + len).any(|p| p.value.noexec)
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
            self.areas.clear(a, b);
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
                held: None,
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
                    label: None,
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

    /// Whether mappings made from now on are locked (`MCL_FUTURE`).
    pub fn locks_future(&self) -> bool {
        self.lock_future
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
    /// The mapping `addr` is in, whole: its start and end.
    pub fn span_at(&self, addr: u64) -> Option<(u64, u64)> {
        self.areas.get(addr).map(|p| (p.start, p.end))
    }

    /// Whether file `dev`, `ino` is mapped shared and writable.
    pub fn shared_writable(&self, dev: u64, ino: u64) -> bool {
        self.areas.iter().any(|p| {
            let o = &p.value.object;
            p.value.shared && p.value.prot & mman::PROT_WRITE != 0 && (o.dev, o.ino) == (dev, ino)
        })
    }

    /// How many mappings there are (what `vm.max_map_count` limits).
    pub fn count(&self) -> usize {
        self.areas.len() + usize::from(self.pending.is_some())
    }

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
    PAGE.store(page, Relaxed);
}

/// The guest's page size.
pub fn page_size() -> u64 {
    PAGE.load(Relaxed)
}

/// This process's record.
static RECORD: Mutex<Record> = Mutex::new(Record::new());

/// How many mappings the record holds, as its lock was last let go: read
/// without the lock by every `mmap` ([`count`]).
static COUNT: AtomicUsize = AtomicUsize::new(0);

/// Whether mappings made from now on are locked (`mlockall(MCL_FUTURE)`),
/// as the record's lock was last let go: read without the lock by every
/// `mmap` ([`locks_future`]).
static LOCKS_FUTURE: AtomicBool = AtomicBool::new(false);

/// Whether some memory was sealed, as the record's lock was last let go:
/// until then no call looks for a seal ([`may_be_sealed`]).
static ANY_SEALED: AtomicBool = AtomicBool::new(false);

/// The record, locked; its count, whether it locks future mappings and
/// whether any memory was sealed are published as the lock is let go.
pub struct Held(MutexGuard<'static, Record>);

impl std::ops::Deref for Held {
    type Target = Record;

    fn deref(&self) -> &Record {
        &self.0
    }
}

impl std::ops::DerefMut for Held {
    fn deref_mut(&mut self) -> &mut Record {
        &mut self.0
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        COUNT.store(self.0.count(), Relaxed);
        LOCKS_FUTURE.store(self.0.lock_future, Relaxed);
        ANY_SEALED.store(self.0.any_sealed, Relaxed);
    }
}

/// This process's record, to read or change.
pub fn record() -> Held {
    let mut h = Held(RECORD.lock().unwrap_or_else(|e| e.into_inner()));
    h.0.settle();
    h
}

/// The guest mapped `[start, start + len)` with `prot` (`shared` or
/// private), nothing named: as [`Record::mapped`], but kept apart until
/// something looks, so that one unmapped at once ([`unmapped`]) costs the
/// areas nothing. Returns whether it is locked (`mlockall(MCL_FUTURE)`).
pub fn mapped_plain(start: u64, len: u64, prot: u64, shared: bool) -> bool {
    let mut h = record();
    if h.lock_future {
        return h.mapped(start, len, prot, shared, None);
    }
    h.0.pending = Some((start, len, prot, shared));
    false
}

/// The guest unmapped `[start, start + len)`: the pending mapping if it is
/// that one, else as [`Record::unmapped`].
pub fn unmapped(start: u64, len: u64) {
    let mut h = Held(RECORD.lock().unwrap_or_else(|e| e.into_inner()));
    if h.0.pending.is_some_and(|(s, l, _, _)| (s, l) == (start, len)) {
        // What it replaced goes too (one look where nothing was).
        h.0.pending = None;
        h.unmapped(start, len);
        return;
    }
    h.0.settle();
    h.unmapped(start, len);
}

/// How many mappings the record holds, without its lock: as of the last
/// change, which a call racing with another thread's map may miss as it
/// would with the lock.
pub fn count() -> usize {
    COUNT.load(Relaxed)
}

/// Whether mappings made from now on are locked, without the record's
/// lock: as of the last change, which a call racing with another thread's
/// `mlockall` may miss as it would with the lock.
pub fn locks_future() -> bool {
    LOCKS_FUTURE.load(Relaxed)
}

/// Whether any memory may be sealed, without the record's lock: false
/// until some was (a seal is made under the kernel lock, which every call
/// that looks for one holds).
pub fn may_be_sealed() -> bool {
    ANY_SEALED.load(Relaxed)
}

/// Forget every mapping (the old program's, at `execve`).
pub fn clear() {
    *record() = Record::new();
}

/// Run `f` holding the record's lock (see [`crate::fork_locked`]).
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
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

/// The process is ending: its mappings are published no more.
static ENDED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The process is ending: its published mappings go, and are published no
/// more.
pub fn close_for_exit() {
    ENDED.store(true, std::sync::atomic::Ordering::SeqCst);
    let _turn = OUTBOX.lock().unwrap_or_else(|e| e.into_inner());
    crate::procstore::put_own(crate::procstore::Kind::Maps, None);
}

/// Taken while this process publishes its mappings (its threads take
/// turns): other processes read them from its entry in the process store
/// ([`crate::procstore`]) for `/proc/<pid>/maps`.
pub(crate) static OUTBOX: Mutex<()> = Mutex::new(());

/// This process's mappings encoded as [`publish`] publishes them.
pub fn snapshot() -> Vec<u8> {
    let mut e = crate::snapshot::Enc::with_capacity(LAST_SIZE.load(Relaxed));
    snapshot_into(&mut e);
    let bytes = e.into_bytes();
    LAST_SIZE.store(bytes.len(), Relaxed);
    bytes
}

/// The size of the mappings last encoded: room to encode them again in.
static LAST_SIZE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// [`snapshot`], written into `e`.
fn snapshot_into(e: &mut crate::snapshot::Enc) {
    // The host's view first: its lock comes before the record's.
    let tracked = crate::mm::tracked();
    let translations = crate::uaccess::translations();
    record().encode(e);
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
}

/// In a fork child: its mappings, which are its parent's, for the record
/// it writes as it starts (see [`crate::procreg::own_line`]). It publishes
/// its own only once they change.
pub fn forked() -> Vec<u8> {
    snapshot()
}

/// The mappings changed since they were last published.
static STALE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// This process's mappings changed: they are published before its next
/// call that is not a memory call ([`flush`]). No other process can learn
/// of a mapping before then, and a run of mapping calls (a program making
/// thousands) publishes them once, not once each.
pub fn publish() {
    STALE.store(true, Relaxed);
}

/// Before system call `nr`: publish the mappings if they changed, unless
/// `nr` is a memory call (one that only changes them again: a System V
/// segment's attachment or detachment too).
#[cfg_attr(
    target_os = "macos",
    unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
)]
pub fn flush_before(nr: u64) {
    use fwe_abi::nr as n;
    if !matches!(
        nr,
        n::MMAP
            | n::MUNMAP
            | n::MPROTECT
            | n::MREMAP
            | n::MADVISE
            | n::BRK
            | n::MLOCK
            | n::MLOCK2
            | n::MUNLOCK
            | n::MINCORE
            | n::SHMAT
            | n::SHMDT
    ) {
        flush();
    }
}

/// Publish the mappings if they changed since last published.
pub fn flush() {
    use Relaxed;
    // Read first: a swap would write the flag's line on every call, which
    // every thread's calls then contend for.
    if STALE.load(Relaxed) && STALE.swap(false, Relaxed) {
        publish_now();
    }
}

/// Publish this process's mappings for other processes to read now.
pub fn publish_now() {
    // After when the process started: a reader tells them from an earlier
    // process's of the same pid that was killed before it could take its
    // own away.
    let me = crate::host::pid();
    let mut e = crate::snapshot::Enc::with_capacity(8 + LAST_SIZE.load(Relaxed));
    e.u64(crate::procreg::start_time(me).unwrap_or(0));
    snapshot_into(&mut e);
    let body = e.into_bytes();
    LAST_SIZE.store(body.len(), Relaxed);
    let _turn = OUTBOX.lock().unwrap_or_else(|e| e.into_inner());
    if ENDED.load(std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    crate::procstore::put_own(crate::procstore::Kind::Maps, Some(&body));
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
    let published = crate::procstore::get_of(crate::procstore::Kind::Maps, pid).filter(|b| {
        b.get(..8).map(|s| u64::from_le_bytes(s.try_into().unwrap()))
            == crate::procreg::start_time(pid)
    });
    match published {
        Some(body) => decode_published(&body[8..]),
        None => {
            // None published yet: what it was forked with.
            let r = crate::procreg::read(pid)?;
            (!r.maps.is_empty()).then(|| decode_published(&r.maps)).flatten()
        }
    }
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
        Name::Anonymous => (a.label.as_deref().unwrap_or_default(), (0, 0)),
        Name::Heap => (b"[heap]", (0, 0)),
        Name::Stack => (b"[stack]", (0, 0)),
        Name::Exe => (exe.path, exe.id),
        Name::Path(p) => (p, (a.object.dev, a.object.ino)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A plain mapping kept apart is in the record for anyone who looks,
    /// counted meanwhile, and one unmapped whole at once leaves nothing.
    #[test]
    fn a_pending_mapping_is_seen_by_readers_and_dropped_by_its_unmap() {
        let (a, b, len) = (0x7a00_0000_0000u64, 0x7b00_0000_0000u64, 0x4000u64);
        let before = record().count();
        mapped_plain(a, len, 3, false);
        assert_eq!(count(), before + 1);
        unmapped(a, len);
        assert_eq!(record().span_at(a), None);
        assert_eq!(record().count(), before);
        mapped_plain(b, len, 3, false);
        assert_eq!(record().span_at(b), Some((b, b + len)));
        unmapped(b, len);
        assert_eq!(record().span_at(b), None);
        // One made over another (`MAP_FIXED`) and unmapped at once takes
        // the one it replaced with it.
        record().mapped(a, 4 * len, 1, false, None);
        mapped_plain(a + len, len, 3, false);
        unmapped(a + len, len);
        assert_eq!(record().span_at(a + len), None);
        assert_eq!(record().span_at(a), Some((a, a + len)));
        unmapped(a, 4 * len);
        assert_eq!(record().count(), before);
    }

    fn file(path: &str, offset: u64) -> Option<Object> {
        Some(Object {
            name: Name::Path(path.as_bytes().into()),
            dev: 0x803,
            ino: 42,
            offset,
            held: None,
        })
    }

    /// `continues` tells what comparing with `at` tells, for every field
    /// that can differ.
    #[test]
    fn continuing_is_comparing_the_moved_mapping() {
        use crate::vmas::Mapping;
        let base = Area {
            prot: mman::PROT_READ,
            shared: false,
            locked: false,
            noexec: false,
            nowrite: false,
            sealed: false,
            object: file("/lib/x.so", 0x1000).unwrap(),
            label: None,
        };
        let anon = Area { object: Object::anonymous(Name::Anonymous), ..base.clone() };
        let mut others = vec![base.at(0x4000), base.at(0x8000), anon.clone(), anon.at(0x4000)];
        for change in [
            |a: &mut Area| a.prot = mman::PROT_READ | mman::PROT_WRITE,
            |a: &mut Area| a.shared = true,
            |a: &mut Area| a.locked = true,
            |a: &mut Area| a.noexec = true,
            |a: &mut Area| a.nowrite = true,
            |a: &mut Area| a.sealed = true,
            |a: &mut Area| a.object.dev += 1,
            |a: &mut Area| a.object.ino += 1,
            |a: &mut Area| a.object.name = Name::Path(b"/lib/y.so"[..].into()),
            |a: &mut Area| a.object.name = Name::Heap,
            |a: &mut Area| a.label = Some(b"[anon:x]"[..].into()),
        ] {
            let mut a = base.at(0x4000);
            change(&mut a);
            others.push(a);
        }
        for first in [&base, &anon] {
            for next in &others {
                for offset in [0, 0x4000, 0x8000] {
                    assert_eq!(
                        first.continues(offset, next),
                        first.at(offset) == *next,
                        "{first:?} at {offset:#x} against {next:?}"
                    );
                }
            }
        }
    }

    /// Anonymous memory takes a name, which the listing shows and which
    /// splits it from the rest; a file's mapping takes none (`EBADF`); a
    /// hole is `ENOMEM` once the rest is named.
    #[test]
    fn anonymous_memory_is_named() {
        let mut r = Record::new();
        let rw = mman::PROT_READ | mman::PROT_WRITE;
        r.mapped(0x10000, 0xc000, rw, false, None);
        r.mapped(0x20000, 0x4000, rw, true, None);
        r.mapped(0x30000, 0x4000, rw, false, file("/lib/a.so", 0));
        assert_eq!(r.set_anon_name(0x14000, 0x18000, Some(b"buf")), Ok(()));
        assert_eq!(r.set_anon_name(0x20000, 0x24000, Some(b"shm")), Ok(()));
        assert_eq!(r.set_anon_name(0x2c000, 0x34000, Some(b"x")), Err(fwe_abi::errno::EBADF));
        assert_eq!(r.set_anon_name(0x18000, 0x20000, Some(b"y")), Err(fwe_abi::errno::ENOMEM));
        let text = String::from_utf8(render(
            &r.areas(),
            &Exe { path: b"/bin/x", id: (0, 0) },
            0x4000,
            None,
        ))
        .unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines[0].starts_with("00010000-00014000 rw-p") && lines[0].ends_with(" 0 "));
        assert!(lines[1].starts_with("00014000-00018000 ") && lines[1].ends_with("[anon:buf]"));
        assert!(lines[2].starts_with("00018000-0001c000 ") && lines[2].ends_with("[anon:y]"));
        assert!(lines[3].ends_with("[anon_shmem:shm]"), "{text}");
        assert_eq!(r.set_anon_name(0x14000, 0x18000, None), Ok(()));
        assert!(r.areas()[0].value.label.is_none());
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
