//! Translations kept: the blocks made from a file's code, kept on disk by
//! the file's identity and where it is loaded, and taken again by a later
//! process (or this one) that comes to the same code, as prepared images
//! are kept ([`fwe_kernel::prepcache`]). A block taken again is what
//! [`translate`] made, before it was placed: its words, what each stands
//! for, its branches to resolve and its calls; placing it is as for a
//! block just made.
//!
//! A record holds the program's words the block was made from, and the
//! calls made in other blocks' words that its translation went on into
//! ([`State::calls_made`]): it is taken only where both are as they are now,
//! so a block whose code changed, or that the state around it would make
//! otherwise, is made afresh. Translations depend on fwe's own code and the
//! thread's slots they name, so the records are kept apart for each build
//! of fwe (its image's UUID) and those slots; another build's go once they
//! are an hour old.
//!
//! The records of a file loaded at an address are files of their own in a
//! directory ([`Part`]): each process adds the records it made as one
//! more, written aside and moved into place, and maps them read-only to
//! take records from; one that finds many merges them into one.

use super::{Calls, Made, Packed, Room};
use crate::asm::{Asm, Field, Pos, Sec};
use crate::jitcount;
use std::collections::HashMap;
use std::os::unix::ffi::OsStrExt;
use std::sync::Mutex;

/// Where a file's code is: the file (Linux's device and inode) and the
/// address its start is mapped at.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(super) struct Part {
    dev: u64,
    ino: u64,
    base: u64,
}

/// A record's place: its file of records, offset and length.
#[derive(Clone, Copy)]
struct At {
    seg: u32,
    off: u32,
    len: u32,
}

/// A file of records mapped read-only.
struct Seg {
    ptr: *const u8,
    len: usize,
    path: Vec<u8>,
}

// SAFETY: a read-only mapping, never written; unmapped only when dropped.
unsafe impl Send for Seg {}

impl Seg {
    fn bytes(&self) -> &[u8] {
        // SAFETY: the mapping lives as long as `self`.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl Drop for Seg {
    fn drop(&mut self) {
        // SAFETY: the mapping `self` made.
        unsafe { libc::munmap(self.ptr as *mut libc::c_void, self.len) };
    }
}

/// A part's records, as this process found them.
#[derive(Default)]
struct Loaded {
    segs: Vec<Seg>,
    index: HashMap<u64, Vec<At>>,
}

/// What this process knows of the records: the parts it looked at, the
/// last mapping it found a part in (start, end and part, or none for code
/// not from a file), and the records it made, by part, to add as it ends
/// (made by process `owner`: a fork child does not add its parent's).
struct Kept {
    parts: HashMap<Part, Loaded>,
    last: Option<(u64, u64, Option<Part>)>,
    new: HashMap<Part, Vec<(u64, Vec<u8>)>>,
    owner: i32,
}

static KEPT: Mutex<Option<Kept>> = Mutex::new(None);

/// The program's file (host device and inode): what names the part of its
/// mappings ([`fwe_kernel::maps::Name::Exe`], which the record names by no
/// file of its own).
static PROGRAM: Mutex<Option<(u64, u64)>> = Mutex::new(None);

/// The program's file is `id` ([`PROGRAM`]).
pub(super) fn program_is(id: Option<(u64, u64)>) {
    *PROGRAM.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = id;
    if let Some(k) = kept().as_mut() {
        k.last = None;
    }
}

/// In a fork child: the records it makes are its own to add, not its
/// parent's again.
pub(super) fn forked() {
    if let Some(k) = kept().as_mut() {
        k.new.clear();
        k.owner = fwe_kernel::host::pid();
    }
}

fn kept() -> std::sync::MutexGuard<'static, Option<Kept>> {
    KEPT.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The part the code at `g` is in, if it is a file's.
pub(super) fn part_of(g: u64) -> Option<Part> {
    let mut k = kept();
    let k = k.get_or_insert_with(|| Kept {
        parts: HashMap::new(),
        last: None,
        new: HashMap::new(),
        owner: fwe_kernel::host::pid(),
    });
    if let Some((start, end, part)) = k.last
        && (start..end).contains(&g)
    {
        return part;
    }
    let areas = fwe_kernel::maps::record().areas_in(g, g + 4);
    let a = areas.first()?;
    let o = &a.value.object;
    let file = match o.name {
        fwe_kernel::maps::Name::Path(_) => Some((o.dev, o.ino)),
        fwe_kernel::maps::Name::Exe => {
            *PROGRAM.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
        }
        _ => None,
    };
    let part = file.map(|(dev, ino)| Part { dev, ino, base: a.start.wrapping_sub(o.offset) });
    k.last = Some((a.start, a.end, part));
    part
}

/// Forget where mappings are: `[addr, addr + len)` was mapped anew.
pub(super) fn remapped(addr: u64, len: u64) {
    if let Some(k) = kept().as_mut()
        && let Some((start, end, _)) = k.last
        && start < addr.saturating_add(len)
        && addr < end
    {
        k.last = None;
    }
}

/// A record of part `part` for the block at `g` made from `source` (its
/// words, as far as it read them) with the calls in `known` made in other
/// blocks' words: the block as made, its words' meanings packed, and where
/// its words end.
pub(super) fn take(
    part: Part,
    g: u64,
    source: &[u32],
    known: impl Fn(u64) -> Vec<u64>,
) -> Option<(Made, Vec<Packed>)> {
    let mut k = kept();
    let k = k.as_mut()?;
    let loaded = k.parts.entry(part).or_insert_with(|| load(part));
    for at in loaded.index.get(&g)? {
        let seg = loaded.segs.get(at.seg as usize)?;
        let rec = seg.bytes().get(at.off as usize..(at.off + at.len) as usize)?;
        let mut r = Reader(rec);
        let n = r.u32()? as usize;
        let words: Vec<u32> = (0..n).map(|_| r.u32()).collect::<Option<_>>()?;
        if source.get(..n) != Some(&words[..]) {
            continue;
        }
        let end = g + 4 * n as u64;
        let calls: Vec<u64> = (0..r.u32()?).map(|_| r.u64()).collect::<Option<_>>()?;
        if calls != known(end) {
            jitcount::KEPT_OTHER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            continue;
        }
        return decode(&mut r, end);
    }
    None
}

/// Keep the block at `g` of part `part`, made from `source` with the calls
/// `known` (in its words, made in other blocks'), as `made`, its words'
/// meanings `info`.
pub(super) fn keep(
    part: Part,
    g: u64,
    source: &[u32],
    known: &[u64],
    made: &Made,
    info: &[Packed],
) {
    let mut w = Vec::with_capacity(64 + 4 * source.len() + 20 * info.len());
    let put32 = |w: &mut Vec<u8>, v: u32| w.extend_from_slice(&v.to_le_bytes());
    let put64 = |w: &mut Vec<u8>, v: u64| w.extend_from_slice(&v.to_le_bytes());
    put32(&mut w, source.len() as u32);
    for &x in source {
        put32(&mut w, x);
    }
    put32(&mut w, known.len() as u32);
    for &p in known {
        put64(&mut w, p);
    }
    for v in [made.entry, made.unsaved, made.x18, made.second.unwrap_or(usize::MAX)] {
        put32(&mut w, v as u32);
    }
    // The gate its system calls' and flushes' stubs call, an address of
    // this process's ([`relocate`]).
    put64(&mut w, crate::syscall_gate());
    let asm = &made.room.asm;
    let (hot, cold) = (asm.words(Sec::Hot), asm.words(Sec::Cold));
    put32(&mut w, hot.len() as u32);
    put32(&mut w, cold.len() as u32);
    for &x in hot.iter().chain(cold) {
        put32(&mut w, x);
    }
    for p in info {
        w.extend_from_slice(&p.to_bytes());
    }
    let fixups: Vec<_> = asm.fixups().collect();
    put32(&mut w, fixups.len() as u32);
    for (at, field, to) in fixups {
        w.extend_from_slice(&[at.sec as u8, field as u8, u8::from(to.is_some())]);
        w.push(to.map_or(0, |t| t.sec as u8));
        put32(&mut w, at.k as u32);
        put32(&mut w, to.map_or(0, |t| t.k as u32));
    }
    let c = &made.room.c;
    put32(&mut w, c.calls.len() as u32);
    for &r in &c.calls {
        put64(&mut w, r);
    }
    put32(&mut w, c.pads.len() as u32);
    for &(r, k) in &c.pads {
        put64(&mut w, r);
        put32(&mut w, k as u32);
    }
    put32(&mut w, c.made.len() as u32);
    for &(p, k, held) in &c.made {
        put64(&mut w, p);
        put64(&mut w, k);
        w.push(u8::from(held));
    }
    put32(&mut w, c.joins.len() as u32);
    for &(k, p, _) in &c.joins {
        put32(&mut w, k as u32);
        put64(&mut w, p);
    }
    if let Some(k) = kept().as_mut() {
        k.new.entry(part).or_default().push((g, w));
    }
}

/// The block a record holds, read on from past its words and calls: made
/// again in this thread's room ([`super::ROOM`]), with its words' meanings
/// packed.
fn decode(r: &mut Reader, end: u64) -> Option<(Made, Vec<Packed>)> {
    let [entry, unsaved, x18, second] = [r.u32()?, r.u32()?, r.u32()?, r.u32()?];
    let gate = r.u64()?;
    let (hot, cold) = (r.u32()? as usize, r.u32()? as usize);
    let mut words = [Vec::with_capacity(hot), Vec::with_capacity(cold)];
    for k in 0..hot + cold {
        words[usize::from(k >= hot)].push(r.u32()?);
    }
    let info: Vec<Packed> =
        (0..hot + cold).map(|_| Packed::from_bytes(r.take(16)?)).collect::<Option<_>>()?;
    relocate(&mut words[0], &info[..hot], gate, crate::syscall_gate());
    let field = |v: u8| [Field::Imm26, Field::Imm19, Field::Imm14].get(usize::from(v)).copied();
    let sec = |v: u8| [Sec::Hot, Sec::Cold].get(usize::from(v)).copied();
    let mut fixups = Vec::new();
    for _ in 0..r.u32()? {
        let b = r.take(4)?;
        let (at, to) = (r.u32()? as usize, r.u32()? as usize);
        let target = (b[2] == 1).then(|| Some(Pos { sec: sec(b[3])?, k: to })).flatten();
        if b[2] == 1 && target.is_none() {
            return None;
        }
        fixups.push((Pos { sec: sec(b[0])?, k: at }, field(b[1])?, target));
    }
    let mut room =
        super::ROOM.take().unwrap_or_else(|| Room { asm: Asm::new(), c: Calls::default() });
    room.c.clear();
    room.asm.restore(words, &fixups);
    let c = &mut room.c;
    for _ in 0..r.u32()? {
        c.calls.push(r.u64()?);
    }
    for _ in 0..r.u32()? {
        c.pads.push((r.u64()?, r.u32()? as usize));
    }
    for _ in 0..r.u32()? {
        c.made.push((r.u64()?, r.u64()?, r.take(1)?[0] == 1));
    }
    for _ in 0..r.u32()? {
        // (Where the call's words are now is the state's to say:
        // [`super::translation`] sets it.)
        c.joins.push((r.u32()? as usize, r.u64()?, 0));
    }
    let second = (second != u32::MAX).then_some(second as usize);
    let made = Made {
        room,
        entry: entry as usize,
        unsaved: unsaved as usize,
        x18: x18 as usize,
        end,
        second,
        counters: None,
    };
    Some((made, info))
}

/// The hot words `words` of a block made where the system-call gate was at
/// `was`, for a process whose gate is at `now` (fwe's image lands
/// elsewhere in each): the gate's address in the literal of each system
/// call's and flush's stub (two words among those finishing it,
/// [`Packed::Finish`]) set to `now`.
fn relocate(words: &mut [u32], info: &[Packed], was: u64, now: u64) {
    if was == now {
        return;
    }
    let stub =
        |p: &Packed| matches!(p, Packed::Finish { of: super::Of::Syscall | super::Of::Flush, .. });
    let mut k = 0;
    while k + 1 < words.len() {
        if stub(&info[k])
            && stub(&info[k + 1])
            && (words[k], words[k + 1]) == (was as u32, (was >> 32) as u32)
        {
            words[k] = now as u32;
            words[k + 1] = (now >> 32) as u32;
            k += 2;
        } else {
            k += 1;
        }
    }
}

/// A record's bytes, read in turn.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (a, b) = self.0.split_at_checked(n)?;
        self.0 = b;
        Some(a)
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
}

/// A file of records begins so, then its count of records and for each its
/// program address, offset and length; their bytes follow.
const MAGIC: &[u8; 8] = b"fwekept2";

/// The directory of this build's records, with the thread's slots its
/// translations name ([`crate::thread_pointer_slot`], [`crate::x18_slot`]:
/// keys made as a process starts, the same in every one).
fn build_dir() -> Option<Vec<u8>> {
    let mut d = fwe_kernel::prepcache::beside("translations")?;
    d.extend_from_slice(b"/");
    d.extend(build_id().iter().flat_map(|b| format!("{b:02x}").into_bytes()));
    d.extend_from_slice(
        format!("-{:x}-{:x}", crate::thread_pointer_slot(), crate::x18_slot()).as_bytes(),
    );
    Some(d)
}

/// The directory of part `p`'s records.
fn part_dir(p: Part) -> Option<Vec<u8>> {
    let mut d = build_dir()?;
    d.extend_from_slice(format!("/{:x}-{:x}-{:x}", p.dev, p.ino, p.base).as_bytes());
    Some(d)
}

/// The UUID of fwe's own image, which every build has its own of.
fn build_id() -> [u8; 16] {
    static ID: std::sync::OnceLock<[u8; 16]> = std::sync::OnceLock::new();
    *ID.get_or_init(|| {
        // SAFETY: zeroed is a valid `Dl_info`; dladdr fills it for an
        // address of this image.
        let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        let found = unsafe { libc::dladdr(build_id as *const libc::c_void, &mut info) } != 0;
        assert!(found && !info.dli_fbase.is_null(), "fwe's own image not found");
        let header = info.dli_fbase as *const u32;
        // SAFETY: a mapped Mach-O header and its load commands, read as
        // the loader laid them out: `mach_header_64` is 8 words, then
        // commands of (cmd, cmdsize, ...).
        unsafe {
            let ncmds = header.add(4).read();
            let mut cmd = (header as *const u8).add(32);
            for _ in 0..ncmds {
                let (kind, size) = ((cmd as *const u32).read(), (cmd as *const u32).add(1).read());
                if kind == 0x1b {
                    // LC_UUID
                    return cmd.add(8).cast::<[u8; 16]>().read_unaligned();
                }
                cmd = cmd.add(size as usize);
            }
        }
        panic!("fwe's own image has no UUID");
    })
}

/// Part `p`'s records, mapped.
fn load(p: Part) -> Loaded {
    let mut loaded = Loaded::default();
    let Some(dir) = part_dir(p) else { return loaded };
    let Ok(entries) = std::fs::read_dir(std::ffi::OsStr::from_bytes(&dir)) else { return loaded };
    for e in entries.flatten() {
        let path = e.path();
        if path.extension().is_none_or(|x| x != "rec") {
            continue;
        }
        let Ok(f) = std::fs::File::open(&path) else { continue };
        let Ok(len) = f.metadata().map(|m| m.len() as usize) else { continue };
        if len < 12 || len > u32::MAX as usize {
            continue;
        }
        // SAFETY: a fresh read-only private mapping of the whole file.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                std::os::fd::AsRawFd::as_raw_fd(&f),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            continue;
        }
        let seg = Seg { ptr: ptr as *const u8, len, path: path.as_os_str().as_bytes().to_vec() };
        let k = loaded.segs.len() as u32;
        let mut r = Reader(seg.bytes());
        if r.take(8) != Some(&MAGIC[..]) {
            continue;
        }
        let Some(n) = r.u32() else { continue };
        let mut index = Vec::new();
        for _ in 0..n {
            let (Some(g), Some(off), Some(rlen)) = (r.u64(), r.u32(), r.u32()) else { break };
            if (off as usize).saturating_add(rlen as usize) <= len {
                index.push((g, At { seg: k, off, len: rlen }));
            }
        }
        for (g, at) in index {
            loaded.index.entry(g).or_default().push(at);
        }
        loaded.segs.push(seg);
    }
    loaded
}

/// A file of records `recs` (program address and bytes each).
fn file_of<'a>(recs: impl ExactSizeIterator<Item = (u64, &'a [u8])> + Clone) -> Vec<u8> {
    let n = recs.len();
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(n as u32).to_le_bytes());
    let mut off = 12 + 16 * n;
    for (g, r) in recs.clone() {
        out.extend_from_slice(&g.to_le_bytes());
        out.extend_from_slice(&(off as u32).to_le_bytes());
        out.extend_from_slice(&(r.len() as u32).to_le_bytes());
        off += r.len();
    }
    for (_, r) in recs {
        out.extend_from_slice(r);
    }
    out
}

/// The files of records a part may hold before a process adding one merges
/// them all into one.
const MERGE_AT: usize = 8;

/// Add the records this process made to their parts' directories: as it
/// ends, and before it replaces its program.
pub(super) fn write() {
    let mut k = kept();
    let Some(k) = k.as_mut() else { return };
    let new = std::mem::take(&mut k.new);
    if new.is_empty() || k.owner != fwe_kernel::host::pid() {
        return;
    }
    let Some(build) = build_dir() else { return };
    // The directories, made as needed: the parent's first (private).
    let mkdir = |d: &[u8]| {
        let _ = std::fs::DirBuilder::new().mode(0o700).create(std::ffi::OsStr::from_bytes(d));
    };
    use std::os::unix::fs::DirBuilderExt;
    if let Some(slash) = build.iter().rposition(|&b| b == b'/') {
        mkdir(&build[..slash]);
        forget_other_builds(&build[..slash], &build);
    }
    mkdir(&build);
    for (part, recs) in new {
        let Some(dir) = part_dir(part) else { continue };
        mkdir(&dir);
        let loaded = k.parts.entry(part).or_insert_with(|| load(part));
        let merge = loaded.segs.len() >= MERGE_AT;
        let mut all: Vec<(u64, &[u8])> = recs.iter().map(|(g, r)| (*g, &r[..])).collect();
        if merge {
            for (&g, ats) in &loaded.index {
                for at in ats {
                    let seg = &loaded.segs[at.seg as usize];
                    all.push((g, &seg.bytes()[at.off as usize..(at.off + at.len) as usize]));
                }
            }
        }
        let bytes = file_of(all.iter().copied());
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let name = format!("/{}-{nanos}", fwe_kernel::host::pid());
        let path = [&dir[..], name.as_bytes(), b".rec"].concat();
        let tmp = [&dir[..], name.as_bytes(), b".tmp"].concat();
        let (tmp, path) = (std::ffi::OsStr::from_bytes(&tmp), std::ffi::OsStr::from_bytes(&path));
        if std::fs::write(tmp, &bytes).is_err() || std::fs::rename(tmp, path).is_err() {
            let _ = std::fs::remove_file(tmp);
            continue;
        }
        jitcount::KEPT_WRITTEN.fetch_add(recs.len() as u64, std::sync::atomic::Ordering::Relaxed);
        if merge {
            // (Mapped still, until this process ends.)
            for seg in &loaded.segs {
                let _ = std::fs::remove_file(std::ffi::OsStr::from_bytes(&seg.path));
            }
        }
    }
}

/// Remove the records of other builds of fwe, which this one never reads,
/// once their directory is an hour old (a build in use meanwhile makes its
/// blocks afresh).
fn forget_other_builds(parent: &[u8], ours: &[u8]) {
    let Ok(entries) = std::fs::read_dir(std::ffi::OsStr::from_bytes(parent)) else { return };
    for e in entries.flatten() {
        let path = e.path();
        if path.as_os_str().as_bytes() == ours {
            continue;
        }
        let old = e
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|a| a > std::time::Duration::from_secs(3600));
        if old {
            let _ = std::fs::remove_dir_all(&path);
        }
    }
}
