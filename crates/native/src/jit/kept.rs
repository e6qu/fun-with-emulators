//! Translations kept: the blocks made from a file's code, kept on disk by
//! the file's identity and where it is loaded, and those made from code
//! the program generated, by the program's file and their address; taken
//! again by a later process (or this one) that comes to the same code, as
//! prepared images are kept ([`fwe_kernel::prepcache`]). A block taken again is what
//! [`translate`] made, before it was placed: its words, what each stands
//! for, its branches to resolve and its calls; placing it is as for a
//! block just made.
//!
//! A record holds the program's words the block was made from (and those
//! past them its translation looked at), and the calls made in other
//! blocks' words that its translation went on into
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
//!
//! Code a program generates seldom comes again at the same address with
//! the same words (a runtime's compilers place what they make as they
//! go), and a record costs about as much to make as the block. So each
//! generated block made is only noted, by its address and its words' key
//! ([`Seen`]), and its record is kept only once a process makes it again,
//! where a past one noted it: from then on, later processes take it.

use super::{Calls, Made, Packed, Room};
use crate::asm::{Asm, Field, Pos, Sec, To};
use crate::jitcount;
use std::collections::HashMap;
use std::os::unix::ffi::OsStrExt;
use std::sync::Mutex;

/// Where a file's code is: the file (Linux's device and inode) and the
/// address its start is mapped at; or code a program generated: the
/// program's file, and [`GENERATED`] for an address (its records name
/// theirs whole).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(super) struct Part {
    dev: u64,
    ino: u64,
    base: u64,
}

/// [`Part::base`] of code a program generated: no address a file's start
/// is mapped at (not page-aligned).
const GENERATED: u64 = u64::MAX;

/// The part of code the program generated: by the program's file, if it
/// has one.
pub(super) fn generated() -> Option<Part> {
    let program = *PROGRAM.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    program.map(|(dev, ino)| Part { dev, ino, base: GENERATED })
}

/// A record's entry in its file's table: its program address, offset,
/// length and key ([`key_of`]), which a block is looked for by before its
/// record is read.
#[derive(Clone, Copy)]
struct At {
    g: u64,
    off: u32,
    len: u32,
    key: u64,
}

/// The bytes of an entry of a file's table ([`file_of`]).
const ENTRY: usize = 24;

/// The key of a record made from the program's words `words`: how many
/// they are, in the top 16 bits, and a hash of them (FNV-1a) in the rest.
fn key_of(words: impl Iterator<Item = u32>) -> u64 {
    let (mut n, mut h) = (0u64, 0xcbf2_9ce4_8422_2325u64);
    for w in words {
        h = (h ^ u64::from(w)).wrapping_mul(0x100_0000_01b3);
        n += 1;
    }
    (n.min(0xffff) << 48) | (h & ((1 << 48) - 1))
}

/// The most records an address keeps in a part's files: those of the
/// processes that made one last. A merge leaves out older ones.
const PER_ADDRESS: usize = 8;

/// A file of records mapped read-only, its table of `n` entries checked
/// to lie within it.
struct Seg {
    ptr: *const u8,
    len: usize,
    n: usize,
    path: Vec<u8>,
}

// SAFETY: a read-only mapping, never written; unmapped only when dropped.
unsafe impl Send for Seg {}

impl Seg {
    fn bytes(&self) -> &[u8] {
        // SAFETY: the mapping lives as long as `self`.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    /// Entry `i` of its table.
    fn entry(&self, i: usize) -> At {
        let e = &self.bytes()[12 + ENTRY * i..12 + ENTRY * (i + 1)];
        let u32_at = |k: usize| u32::from_le_bytes([e[k], e[k + 1], e[k + 2], e[k + 3]]);
        let u64_at = |k: usize| u64::from(u32_at(k)) | u64::from(u32_at(k + 4)) << 32;
        At { g: u64_at(0), off: u32_at(8), len: u32_at(12), key: u64_at(16) }
    }

    /// Its entries for program address `g` (the table is in address
    /// order), found by halves: no index of them made.
    fn entries(&self, g: u64) -> impl Iterator<Item = At> + '_ {
        let mut lo = 0;
        let mut hi = self.n;
        while lo < hi {
            let mid = (lo + hi) / 2;
            if self.entry(mid).g < g { lo = mid + 1 } else { hi = mid }
        }
        (lo..self.n).map(|i| self.entry(i)).take_while(move |e| e.g == g)
    }

    /// The bytes of the record at `at`, if they lie within the file.
    fn record(&self, at: At) -> Option<&[u8]> {
        self.bytes().get(at.off as usize..(at.off as usize).checked_add(at.len as usize)?)
    }
}

impl Drop for Seg {
    fn drop(&mut self) {
        // SAFETY: the mapping `self` made.
        unsafe { libc::munmap(self.ptr as *mut libc::c_void, self.len) };
    }
}

/// A part's files of records, as this process found them: oldest first;
/// for code the program generated, the addresses they have records for,
/// and the blocks past processes noted.
#[derive(Default)]
struct Loaded {
    segs: Vec<Seg>,
    addresses: Option<std::collections::HashSet<u64, Fast>>,
    seen: Option<Seen>,
}

/// The generated blocks past processes made, noted by their address and
/// words' key ([`note_of`]): a table of notes found by their value
/// (open addressing, 0 for an empty slot), mapped read-only. Each process
/// that made some writes the table again with its own added, the oldest
/// left out past [`SEEN_MOST`].
struct Seen {
    map: Seg,
    slots: usize,
}

/// The file a part's notes are in, in its directory.
const SEEN_FILE: &[u8] = b"/seen";

/// A table of notes begins so, then its count of slots (a power of two),
/// and the slots.
const SEEN_MAGIC: &[u8; 8] = b"fweseen1";

/// The most notes a part's table keeps.
const SEEN_MOST: usize = 1 << 19;

/// The note of the generated block at `g` made from words of key `key`:
/// never 0.
fn note_of(g: u64, key: u64) -> u64 {
    let mut x = g ^ key.rotate_left(32);
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    x ^= x >> 33;
    x | 1
}

impl Seen {
    fn slot(&self, i: usize) -> u64 {
        let b = &self.map.bytes()[12 + 8 * i..20 + 8 * i];
        u64::from_le_bytes(b.try_into().expect("8 bytes"))
    }

    /// Whether `note` is in the table.
    fn has(&self, note: u64) -> bool {
        let mask = self.slots - 1;
        let mut i = (note >> 7) as usize & mask;
        loop {
            match self.slot(i) {
                0 => return false,
                v if v == note => return true,
                _ => i = (i + 1) & mask,
            }
        }
    }

    /// Its notes.
    fn notes(&self) -> impl Iterator<Item = u64> + '_ {
        (0..self.slots).map(|i| self.slot(i)).filter(|&v| v != 0)
    }
}

/// A table of `notes` (none 0, none twice), as [`Seen`] reads it.
fn seen_file(notes: &[u64]) -> Vec<u8> {
    let slots = (2 * notes.len()).next_power_of_two().max(2);
    let mask = slots - 1;
    let mut table = vec![0u64; slots];
    for &v in notes {
        let mut i = (v >> 7) as usize & mask;
        while table[i] != 0 {
            i = (i + 1) & mask;
        }
        table[i] = v;
    }
    let mut out = Vec::with_capacity(12 + 8 * slots);
    out.extend_from_slice(SEEN_MAGIC);
    out.extend_from_slice(&(slots as u32).to_le_bytes());
    for v in table {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out
}

/// What this process knows of the records: the parts it looked at, the
/// last mapping it found a part in (start, end and part, or none for code
/// not from a file), and the records it made, by part, to add as it ends
/// (made by process `owner`: a fork child does not add its parent's).
struct Kept {
    parts: HashMap<Part, Loaded, Fast>,
    last: Option<(u64, u64, Option<Part>)>,
    new: HashMap<Part, New, Fast>,
    owner: i32,
}

/// The hashing of the maps looked in for each block made: an address's
/// ([`super::AddrHash`]).
type Fast = std::hash::BuildHasherDefault<super::AddrHash>;

/// A part's records made in this process: each one's program address and
/// its bytes' end, the bytes one after another; and the generated blocks
/// it made, noted ([`Seen`]).
#[derive(Default)]
struct New {
    ends: Vec<(u64, usize)>,
    bytes: Vec<u8>,
    noted: Vec<u64>,
}

impl New {
    /// Each record's program address and bytes.
    fn records(&self) -> impl Iterator<Item = (u64, &[u8])> {
        self.ends.iter().enumerate().map(|(k, &(g, end))| {
            let start = if k == 0 { 0 } else { self.ends[k - 1].1 };
            (g, &self.bytes[start..end])
        })
    }
}

/// Words `ws` added to `w`, little-endian, at once.
fn put_words(w: &mut Vec<u8>, ws: &[u32]) {
    let at = w.len();
    w.resize(at + 4 * ws.len(), 0);
    for (d, x) in w[at..].as_chunks_mut::<4>().0.iter_mut().zip(ws) {
        *d = x.to_le_bytes();
    }
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

/// [`KEPT`], begun if it was not.
fn begun(k: &mut Option<Kept>) -> &mut Kept {
    k.get_or_insert_with(|| Kept {
        parts: HashMap::default(),
        last: None,
        new: HashMap::default(),
        owner: fwe_kernel::host::pid(),
    })
}

/// The part the code at `g` is in, if it is a file's.
pub(super) fn part_of(g: u64) -> Option<Part> {
    let mut k = kept();
    let k = begun(&mut k);
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

/// A record of part `part` for the block at `g` made from `source` (the
/// program's words from `g`, as far as a block's translation may read
/// them) with the calls in `known` made in other blocks' words: the block
/// as made, its words' meanings packed, and where its words end.
pub(super) fn take(
    part: Part,
    g: u64,
    source: &[u32],
    known: impl Fn(u64) -> Vec<u64>,
) -> Option<(Made, Vec<Packed>)> {
    let mut k = kept();
    let k = begun(&mut k);
    let loaded = k.parts.entry(part).or_insert_with(|| load(part));
    if loaded.addresses.as_ref().is_some_and(|a| !a.contains(&g)) {
        return None;
    }
    // The keys of the program's words there, as many as each record was
    // made from.
    let mut keys = HashMap::new();
    for (seg, at) in loaded.segs.iter().rev().flat_map(|seg| seg.entries(g).map(move |e| (seg, e)))
    {
        let n = (at.key >> 48) as usize;
        let want = *keys.entry(n).or_insert_with(|| {
            (n <= source.len()).then(|| key_of(source[..n.min(source.len())].iter().copied()))
        });
        if want != Some(at.key) {
            continue;
        }
        jitcount::KEPT_READ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let Some(rec) = seg.record(at) else { continue };
        let mut r = Reader(rec);
        let n = r.u32()? as usize;
        let words = r.take(4 * n)?;
        if source.len() < n || !words_of(words).zip(source).all(|(a, &b)| a == b) {
            continue;
        }
        let end = g + 4 * u64::from(r.u32()?);
        let calls: Vec<u64> = (0..r.u32()?).map(|_| r.u64()).collect::<Option<_>>()?;
        if calls != known(end) {
            jitcount::KEPT_OTHER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            continue;
        }
        return decode(&mut r, end);
    }
    None
}

/// Keep the block at `g` of part `part`, made from `source` (the words its
/// translation read, its own and those it looked at past them) with the
/// calls `known` (in its words, made in other blocks'), as `made`, its
/// words' meanings `info`.
pub(super) fn keep(
    part: Part,
    g: u64,
    source: &[u32],
    known: &[u64],
    made: &Made,
    info: &[Packed],
) {
    let mut k = kept();
    let k = begun(&mut k);
    if part.base == GENERATED {
        // Noted; kept only if a past process made it too.
        let note = note_of(g, key_of(source.iter().copied()));
        k.new.entry(part).or_default().noted.push(note);
        let loaded = k.parts.entry(part).or_insert_with(|| load(part));
        let again = loaded.seen.as_ref().is_some_and(|t| t.has(note));
        if !again {
            return;
        }
        jitcount::NOTED_AGAIN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    let new = k.new.entry(part).or_default();
    let w = &mut new.bytes;
    let put32 = |w: &mut Vec<u8>, v: u32| w.extend_from_slice(&v.to_le_bytes());
    let put64 = |w: &mut Vec<u8>, v: u64| w.extend_from_slice(&v.to_le_bytes());
    put32(w, source.len() as u32);
    put_words(w, source);
    put32(w, ((made.end - g) / 4) as u32);
    put32(w, known.len() as u32);
    for &p in known {
        put64(w, p);
    }
    for v in [made.entry, made.unsaved, made.x18, made.second.unwrap_or(usize::MAX)] {
        put32(w, v as u32);
    }
    // The gate its system calls' and flushes' stubs call, an address of
    // this process's ([`relocate`]).
    put64(w, crate::syscall_gate());
    let asm = &made.room.asm;
    let (hot, cold) = (asm.words(Sec::Hot), asm.words(Sec::Cold));
    put32(w, hot.len() as u32);
    put32(w, cold.len() as u32);
    put_words(w, hot);
    put_words(w, cold);
    for &p in info {
        p.put(w);
    }
    // The fixups' count, set once they are written.
    let count = w.len();
    put32(w, 0);
    let mut fixups = 0u32;
    for (at, field, to) in asm.fixups() {
        // Where it goes: the exit stub (0), a word of the block (1), or
        // the chunk's return tail (2).
        let (kind, to) = match to {
            To::Stub => (0, Pos::hot(0)),
            To::At(p) => (1, p),
            To::Tail => (2, Pos::hot(0)),
        };
        w.extend_from_slice(&[at.sec as u8, field as u8, kind, to.sec as u8]);
        put32(w, at.k as u32);
        put32(w, to.k as u32);
        fixups += 1;
    }
    w[count..count + 4].copy_from_slice(&fixups.to_le_bytes());
    let c = &made.room.c;
    put32(w, c.calls.len() as u32);
    for &r in &c.calls {
        put64(w, r);
    }
    put32(w, c.pads.len() as u32);
    for &(r, k) in &c.pads {
        put64(w, r);
        put32(w, k as u32);
    }
    put32(w, c.made.len() as u32);
    for &(p, k, held) in &c.made {
        put64(w, p);
        put64(w, k);
        w.push(u8::from(held));
    }
    put32(w, c.joins.len() as u32);
    for &(k, p, _) in &c.joins {
        put32(w, k as u32);
        put64(w, p);
    }
    let end = w.len();
    new.ends.push((g, end));
}

/// The block a record holds, read on from past its words and calls: made
/// again in this thread's room ([`super::ROOM`]), with its words' meanings
/// packed.
fn decode(r: &mut Reader, end: u64) -> Option<(Made, Vec<Packed>)> {
    let [entry, unsaved, x18, second] = [r.u32()?, r.u32()?, r.u32()?, r.u32()?];
    let gate = r.u64()?;
    let (hot, cold) = (r.u32()? as usize, r.u32()? as usize);
    let (h, c) = (r.take(4 * hot)?, r.take(4 * cold)?);
    let mut words = [words_of(h).collect::<Vec<_>>(), words_of(c).collect()];
    let mut info = Vec::with_capacity(hot + cold);
    for _ in 0..hot + cold {
        let (p, n) = Packed::read(r.0)?;
        r.take(n)?;
        info.push(p);
    }
    relocate(&mut words[0], &info[..hot], gate, crate::syscall_gate());
    let field = |v: u8| [Field::Imm26, Field::Imm19, Field::Imm14].get(usize::from(v)).copied();
    let sec = |v: u8| [Sec::Hot, Sec::Cold].get(usize::from(v)).copied();
    let mut fixups = Vec::new();
    for _ in 0..r.u32()? {
        let b = r.take(4)?;
        let (at, to) = (r.u32()? as usize, r.u32()? as usize);
        let target = match b[2] {
            0 => To::Stub,
            1 => To::At(Pos { sec: sec(b[3])?, k: to }),
            2 => To::Tail,
            _ => return None,
        };
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
/// The little-endian words of `b`.
fn words_of(b: &[u8]) -> impl Iterator<Item = u32> + '_ {
    b.as_chunks::<4>().0.iter().map(|&w| u32::from_le_bytes(w))
}

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

/// A file of records begins so, then its count of records and a table of
/// them in address order, for each its program address, offset, length
/// and key ([`key_of`]); their bytes follow.
const MAGIC: &[u8; 8] = b"fwekept7";

/// The directory of this build's records, with the thread's slots its
/// translations name ([`crate::thread_pointer_slot`], [`crate::x18_slot`],
/// [`crate::parked_slots`]: keys made as a process starts, the same in
/// every one).
fn build_dir() -> Option<Vec<u8>> {
    let mut d = fwe_kernel::prepcache::beside("translations")?;
    d.extend_from_slice(b"/");
    d.extend(build_id().iter().flat_map(|b| format!("{b:02x}").into_bytes()));
    let (s16, s17) = crate::parked_slots();
    d.extend_from_slice(
        format!("-{:x}-{:x}-{s16:x}-{s17:x}", crate::thread_pointer_slot(), crate::x18_slot())
            .as_bytes(),
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
    let began = fwe_kernel::timing::on().then(std::time::Instant::now);
    let mut loaded = load_files(p);
    if p.base == GENERATED {
        // Few records (those made again): which addresses they are for,
        // so that a block with none is looked for no further.
        let addresses = loaded.segs.iter().flat_map(|s| (0..s.n).map(|i| s.entry(i).g));
        loaded.addresses = Some(addresses.collect());
        loaded.seen = part_dir(p).and_then(|d| load_seen(&[&d[..], SEEN_FILE].concat()));
    }
    if let Some(t) = began {
        let n = loaded.segs.len();
        jitcount::LOADED.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        jitcount::LOAD_NS
            .fetch_add(t.elapsed().as_nanos() as u64, std::sync::atomic::Ordering::Relaxed);
    }
    loaded
}

/// The file at `path` mapped read-only, whole, if it is not empty.
fn map(path: &[u8]) -> Option<Seg> {
    let f = std::fs::File::open(std::ffi::OsStr::from_bytes(path)).ok()?;
    let len = f.metadata().ok()?.len() as usize;
    if len == 0 || len > u32::MAX as usize {
        return None;
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
    (ptr != libc::MAP_FAILED).then(|| Seg { ptr: ptr as *const u8, len, n: 0, path: path.to_vec() })
}

/// A part's table of notes at `path` ([`Seen`]), if it is whole.
fn load_seen(path: &[u8]) -> Option<Seen> {
    let map = map(path)?;
    let mut r = Reader(map.bytes());
    if r.take(8)? != &SEEN_MAGIC[..] {
        return None;
    }
    let slots = r.u32()? as usize;
    (slots.is_power_of_two() && 12 + 8 * slots == map.len).then_some(Seen { map, slots })
}

/// [`load`]'s work: part `p`'s files mapped.
fn load_files(p: Part) -> Loaded {
    let mut loaded = Loaded::default();
    let Some(dir) = part_dir(p) else { return loaded };
    let Ok(entries) = std::fs::read_dir(std::ffi::OsStr::from_bytes(&dir)) else { return loaded };
    // Oldest first, by the time in their names ([`write`]): an address's
    // records end with its newest.
    let mut paths: Vec<std::path::PathBuf> = entries.flatten().map(|e| e.path()).collect();
    paths.sort_by_key(|p| {
        let stem = p.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        stem.rsplit('-').next().and_then(|t| t.parse::<u128>().ok()).unwrap_or(0)
    });
    for path in paths {
        if path.extension().is_none_or(|x| x != "rec") {
            continue;
        }
        let Some(mut seg) = map(path.as_os_str().as_bytes()) else { continue };
        let len = seg.len;
        let mut r = Reader(seg.bytes());
        if r.take(8) != Some(&MAGIC[..]) {
            continue;
        }
        let Some(n) = r.u32() else { continue };
        if 12 + ENTRY * n as usize > len {
            continue;
        }
        seg.n = n as usize;
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
    let mut off = 12 + 24 * n;
    for (g, r) in recs.clone() {
        // (A record begins with the count of the program's words it was
        // made from, and those words: [`keep`].)
        let mut rr = Reader(r);
        let words = rr.u32().and_then(|n| rr.take(4 * n as usize)).unwrap_or_default();
        out.extend_from_slice(&g.to_le_bytes());
        out.extend_from_slice(&(off as u32).to_le_bytes());
        out.extend_from_slice(&(r.len() as u32).to_le_bytes());
        out.extend_from_slice(&key_of(words_of(words)).to_le_bytes());
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
        if !recs.noted.is_empty() {
            write_seen(&dir, &recs.noted, loaded.seen.as_ref());
        }
        if recs.ends.is_empty() {
            continue;
        }
        let merge = loaded.segs.len() >= MERGE_AT;
        let mut all: Vec<(u64, &[u8])> = recs.records().collect();
        if merge {
            // This process's records first, then the files' newest first,
            // at most [`PER_ADDRESS`] for an address.
            let mut count: HashMap<u64, usize> = HashMap::new();
            for &(g, _) in &all {
                *count.entry(g).or_default() += 1;
            }
            for seg in loaded.segs.iter().rev() {
                for at in (0..seg.n).map(|i| seg.entry(i)) {
                    let c = count.entry(at.g).or_default();
                    if *c < PER_ADDRESS
                        && let Some(r) = seg.record(at)
                    {
                        *c += 1;
                        all.push((at.g, r));
                    }
                }
            }
        }
        // (In address order, for [`Seg::entries`].)
        all.sort_by_key(|&(g, _)| g);
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
        jitcount::KEPT_WRITTEN
            .fetch_add(recs.ends.len() as u64, std::sync::atomic::Ordering::Relaxed);
        if merge {
            // (Mapped still, until this process ends.)
            for seg in &loaded.segs {
                let _ = std::fs::remove_file(std::ffi::OsStr::from_bytes(&seg.path));
            }
        }
    }
}

/// Write a part's table of notes in its directory `dir` again: this
/// process's `noted`, and about as many of the table it found, `old`, as
/// fit under [`SEEN_MOST`]: a share of them, each kept by its bits mixed
/// with a salt of this write's (so those left out are spread evenly, the
/// slots they leave too, and a write leaves out its share of what earlier
/// writes kept).
/// Another process writing meanwhile may lose its own: notes only tell
/// which blocks to keep.
fn write_seen(dir: &[u8], noted: &[u64], old: Option<&Seen>) {
    let mut notes: Vec<u64> = noted.to_vec();
    notes.sort_unstable();
    notes.dedup();
    notes.truncate(SEEN_MOST);
    if let Some(t) = old {
        let mine: std::collections::HashSet<u64> = notes.iter().copied().collect();
        let room = (SEEN_MOST - notes.len()) as u64;
        let found = t.notes().count() as u64;
        // Of each 65536, how many to keep.
        let share = if found <= room { 1 << 16 } else { (room << 16) / found };
        let salt = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64);
        let kept = |v: u64| note_of(v, salt) >> 48 < share;
        notes.extend(t.notes().filter(|&v| kept(v) && !mine.contains(&v)));
    }
    let name = format!("{}.tmp", fwe_kernel::host::pid());
    let tmp = [dir, SEEN_FILE, b"-", name.as_bytes()].concat();
    let path = [dir, SEEN_FILE].concat();
    let (tmp, path) = (std::ffi::OsStr::from_bytes(&tmp), std::ffi::OsStr::from_bytes(&path));
    if std::fs::write(tmp, seen_file(&notes)).is_err() || std::fs::rename(tmp, path).is_err() {
        let _ = std::fs::remove_file(tmp);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh directory for a test's files.
    fn dir(name: &str) -> Vec<u8> {
        let d = std::env::temp_dir().join(format!("fwe-seen-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.as_os_str().as_bytes().to_vec()
    }

    /// The longest run of filled slots, wrapping round.
    fn longest_run(t: &Seen) -> usize {
        let (mut best, mut run) = (0, 0);
        for i in 0..2 * t.slots {
            run = if t.slot(i % t.slots) != 0 { run + 1 } else { 0 };
            best = best.max(run);
        }
        best
    }

    /// A table written has its notes and no others, and written again
    /// with more, those too.
    #[test]
    fn notes_are_found_and_others_not() {
        let d = dir("found");
        let notes: Vec<u64> = (0..1000u64).map(|g| note_of(0x4000 + 4 * g, g)).collect();
        write_seen(&d, &notes, None);
        let t = load_seen(&[&d[..], SEEN_FILE].concat()).unwrap();
        assert!(notes.iter().all(|&v| t.has(v)));
        assert!(!(1000..2000u64).any(|g| t.has(note_of(0x4000 + 4 * g, g))));
        let more: Vec<u64> = (1000..1500u64).map(|g| note_of(0x4000 + 4 * g, g)).collect();
        write_seen(&d, &more, Some(&t));
        let t = load_seen(&[&d[..], SEEN_FILE].concat()).unwrap();
        assert!(notes.iter().chain(&more).all(|&v| t.has(v)));
        let _ = std::fs::remove_dir_all(std::ffi::OsStr::from_bytes(&d));
    }

    /// Written again and again past [`SEEN_MOST`], a table keeps about so
    /// many notes, this process's all, and its slots stay spread: no long
    /// run of filled ones for a missing note to walk.
    #[test]
    fn a_full_table_stays_spread() {
        let d = dir("full");
        let path = [&d[..], SEEN_FILE].concat();
        let batch = SEEN_MOST / 2;
        for round in 0..4u64 {
            let old = load_seen(&path);
            let notes: Vec<u64> =
                (0..batch as u64).map(|g| note_of(4 * g, round << 32 | g)).collect();
            write_seen(&d, &notes, old.as_ref());
            let t = load_seen(&path).unwrap();
            assert!(notes.iter().all(|&v| t.has(v)), "round {round}");
            let n = t.notes().count();
            assert!(n <= SEEN_MOST + SEEN_MOST / 64, "round {round}: {n} notes");
            assert!(longest_run(&t) < 200, "round {round}: a run of {}", longest_run(&t));
        }
        let _ = std::fs::remove_dir_all(std::ffi::OsStr::from_bytes(&d));
    }
}
