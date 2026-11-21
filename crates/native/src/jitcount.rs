//! What the translator's work is, counted, for `FWE_TIMING`'s report and
//! the benchmarks' ([`crate::jit`]): the counts that decide which of its
//! work can be skipped.
//!
//! Always, under `FWE_TIMING`: the blocks made by where their code comes
//! from (a file fwe prepared in place, or code the program generated) and
//! the time making them; the blocks made with a second pass of their words
//! for an entry with the program's own `x16` and `x17` (made again with it
//! on that entry's first use), and those whose entry was ever used; the
//! blocks made ahead of the program.
//!
//! With `FWE_JIT_SEEN` naming a directory: each process adds there the
//! blocks it made (their program address and a hash of the words their
//! translation read) as it
//! ends or replaces its program, and counts the blocks it made that an
//! earlier one had: at the same address (and of those, the ones two or
//! more earlier processes made there, which it should have taken from
//! those kept), or the same words elsewhere.
//!
//! With `FWE_JIT_COUNT` set: each block's entries count their runs (its
//! words then differ: a few more at each entry, and every block with an
//! entry for the program's own registers made with a second pass), each
//! way back after a call its returns, and each lookup of a branch or call
//! through a register whether it goes where it went last; at the end, the
//! report says which blocks ran, how often the program's `x16` and `x17`
//! were taken back from their slots (by the instruction) and saved again,
//! how often lookups went where they went last, how often returns came
//! back into generated code, and
//! which pages of generated code hold no word a translation would have to
//! change (a system call, a thread-pointer access, a use of `x18`, a
//! cache flush), with how often those ran and were flushed.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

/// Where a block's code comes from: a file fwe prepared in place, or code
/// the program generated.
pub(crate) const FILE: usize = 0;
pub(crate) const GENERATED: usize = 1;
const ORIGINS: [&str; 2] = ["from files", "generated"];

/// Blocks made, and the nanoseconds making them, by origin.
pub(crate) static MADE: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
pub(crate) static MAKE_NS: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
/// Making or taking a block, by step ([`STEPS`]): the nanoseconds and
/// the times each ran.
pub(crate) static STEP_NS: [AtomicU64; STEPS.len()] = [const { AtomicU64::new(0) }; STEPS.len()];
pub(crate) static STEP_RUNS: [AtomicU64; STEPS.len()] = [const { AtomicU64::new(0) }; STEPS.len()];
pub(crate) const STEP_SNAPSHOT: usize = 0;
pub(crate) const STEP_LOOK: usize = 1;
pub(crate) const STEP_TRANSLATE: usize = 2;
pub(crate) const STEP_CHECK: usize = 3;
pub(crate) const STEP_PACK: usize = 4;
pub(crate) const STEP_KEEP: usize = 5;
pub(crate) const STEP_ROOM: usize = 6;
pub(crate) const STEP_EMIT: usize = 7;
pub(crate) const STEP_INDEX: usize = 8;
pub(crate) const STEP_LINK: usize = 9;
const STEPS: [&str; 10] = [
    "the words read",
    "a kept one looked for",
    "translated (the lock let go and taken again)",
    "the words checked",
    "packed",
    "kept",
    "room found and branches resolved",
    "written and made ready to run",
    "indexed",
    "linked",
];

/// Blocks made with a second pass of their words, those words, the
/// blocks whose entry there was used, and the blocks made again with it
/// (made first without, the pass made on its entry's first use).
pub(crate) static SECOND: AtomicU64 = AtomicU64::new(0);
pub(crate) static SECOND_WORDS: AtomicU64 = AtomicU64::new(0);
pub(crate) static SECOND_USED: AtomicU64 = AtomicU64::new(0);
pub(crate) static SECOND_REMADE: AtomicU64 = AtomicU64::new(0);
/// Blocks made ahead of the program.
pub(crate) static AHEAD: AtomicU64 = AtomicU64::new(0);
/// Blocks taken from those kept ([`crate::jit`]'s `kept`), by origin, and
/// the nanoseconds taking them; records found for a block's words that
/// another block's calls would make otherwise; records added.
pub(crate) static TAKEN: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
pub(crate) static TAKE_NS: AtomicU64 = AtomicU64::new(0);
pub(crate) static KEPT_OTHER: AtomicU64 = AtomicU64::new(0);
/// Records read as a block was looked for: their keys matched its words'.
pub(crate) static KEPT_READ: AtomicU64 = AtomicU64::new(0);
/// Files of records mapped as their parts were first looked at, and the
/// nanoseconds that took.
pub(crate) static LOADED: AtomicU64 = AtomicU64::new(0);
pub(crate) static LOAD_NS: AtomicU64 = AtomicU64::new(0);
pub(crate) static KEPT_WRITTEN: AtomicU64 = AtomicU64::new(0);
/// Generated blocks made where a past process made one from the same
/// words (and so kept).
pub(crate) static NOTED_AGAIN: AtomicU64 = AtomicU64::new(0);
/// Blocks by how their words end ([`ENDS`]), and the program's words they
/// hold (their first pass's).
pub(crate) static ENDED: [AtomicU64; 6] = [const { AtomicU64::new(0) }; 6];
pub(crate) static WORDS: AtomicU64 = AtomicU64::new(0);
pub(crate) const END_BRANCH: usize = 0;
pub(crate) const END_REGISTER: usize = 1;
pub(crate) const END_RETURN: usize = 2;
pub(crate) const END_JOIN: usize = 3;
pub(crate) const END_PAGE: usize = 4;
pub(crate) const END_LENGTH: usize = 5;
const ENDS: [&str; 6] = [
    "a branch",
    "a branch through a register",
    "a return",
    "words made already",
    "the page's end",
    "the most words a block takes",
];

/// The blocks earlier processes made ([`FWE_JIT_SEEN`]), and this one's.
struct Seen {
    dir: std::path::PathBuf,
    /// By program address and hash, how many earlier processes made it.
    at: HashMap<(u64, u64), u32>,
    words: HashSet<u64>,
    made: Vec<(u64, u64)>,
    writes: u32,
}

static SEEN: Mutex<Option<Seen>> = Mutex::new(None);
static SEEN_READ: OnceLock<bool> = OnceLock::new();
/// Of the blocks made, by origin: those an earlier process made at the
/// same address, and those it made of the same words elsewhere.
static REPEATED: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
static MOVED: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
/// Of [`REPEATED`], those two or more earlier processes made.
static TWICE: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];

/// A hash of a block's words (FNV-1a).
fn hash(words: &[u32]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for w in words {
        for b in w.to_le_bytes() {
            h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
        }
    }
    h
}

/// The earlier processes' blocks, read once, if `FWE_JIT_SEEN` names a
/// directory.
fn read_seen() -> bool {
    *SEEN_READ.get_or_init(|| {
        let Some(dir) = std::env::var_os("FWE_JIT_SEEN") else { return false };
        let dir = std::path::PathBuf::from(dir);
        // Each process's blocks ("seen-<pid>-<k>", one file each time it
        // added them), then how many processes made each.
        let mut by_pid: HashMap<String, HashSet<(u64, u64)>> = HashMap::new();
        let mut words = HashSet::new();
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let pid = name.split('-').nth(1).unwrap_or_default().to_string();
            let Ok(text) = std::fs::read_to_string(entry.path()) else { continue };
            for line in text.lines() {
                let mut parts = line.split(' ').map(|p| u64::from_str_radix(p, 16));
                if let (Some(Ok(g)), Some(Ok(h))) = (parts.next(), parts.next()) {
                    by_pid.entry(pid.clone()).or_default().insert((g, h));
                    words.insert(h);
                }
            }
        }
        let mut at: HashMap<(u64, u64), u32> = HashMap::new();
        for block in by_pid.into_values().flatten() {
            *at.entry(block).or_default() += 1;
        }
        *SEEN.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(Seen { dir, at, words, made: Vec::new(), writes: 0 });
        true
    })
}

/// A block made at program address `g` from `words`, of `origin`: counted
/// if an earlier process made it, and kept for the next.
pub(crate) fn seen(g: u64, words: &[u32], origin: usize) {
    if !read_seen() {
        return;
    }
    let h = hash(words);
    let mut seen = SEEN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(s) = seen.as_mut() else { return };
    if let Some(&made) = s.at.get(&(g, h)) {
        REPEATED[origin].fetch_add(1, Ordering::Relaxed);
        if made >= 2 {
            TWICE[origin].fetch_add(1, Ordering::Relaxed);
        }
    } else if s.words.contains(&h) {
        MOVED[origin].fetch_add(1, Ordering::Relaxed);
    }
    s.made.push((g, h));
}

/// Add the blocks this process made since it last did to the directory
/// `FWE_JIT_SEEN` names: as it ends, and before it replaces its program.
pub(crate) fn write_seen() {
    let mut seen = SEEN.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(s) = seen.as_mut() else { return };
    if s.made.is_empty() {
        return;
    }
    let text: String = s.made.iter().map(|(g, h)| format!("{g:x} {h:x}\n")).collect();
    let path = s.dir.join(format!("seen-{}-{}", std::process::id(), s.writes));
    if let Err(e) = std::fs::write(&path, text) {
        eprintln!("fwe: {}: {e}", path.display());
    }
    s.writes += 1;
    s.made.clear();
}

/// Whether blocks count their runs (`FWE_JIT_COUNT`).
pub(crate) fn counting() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("FWE_JIT_COUNT").is_some())
}

/// The counters' room: 8 bytes each, given out in turn.
const UNITS: u64 = 1 << 24;
static AREA: OnceLock<u64> = OnceLock::new();
static NEXT: AtomicU64 = AtomicU64::new(0);

/// The address of `n` new counters, one after another.
pub(crate) fn units(n: u64) -> u64 {
    let base = *AREA.get_or_init(|| {
        // SAFETY: a fresh anonymous mapping, owned by nothing else.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                (8 * UNITS) as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        assert!(p != libc::MAP_FAILED, "no room for the JIT's counters");
        p as u64
    });
    let k = NEXT.fetch_add(n, Ordering::Relaxed);
    assert!(k + n <= UNITS, "more JIT counters than {UNITS}");
    base + 8 * k
}

/// The count at counter `at`.
fn count(at: u64) -> u64 {
    // SAFETY: a counter of [`units`], in its mapping, which lives as long
    // as the process; read as the translations add to it.
    unsafe { (*(at as *const AtomicU64)).load(Ordering::Relaxed) }
}

/// Counters of the program's `x16` and `x17` taken back from their slots
/// for an instruction that names them, and saved there again.
static MOVES: OnceLock<u64> = OnceLock::new();
pub(crate) const RESTORE_NAMED: u64 = 0;
pub(crate) const SAVED_AGAIN: u64 = 1;

/// The counter of `x16` and `x17`'s moves of kind `k` ([`RESTORE_NAMED`]...).
pub(crate) fn moves(k: u64) -> u64 {
    *MOVES.get_or_init(|| units(2)) + 8 * k
}

/// Each place they are taken back for an instruction that names neither
/// (one fwe does not translate with them saved): its counter and the
/// instruction.
static RESTORES: Mutex<Vec<(u64, u32)>> = Mutex::new(Vec::new());

/// A counter for `x16` and `x17` taken back for the program's instruction
/// `w`, which names neither: its address.
pub(crate) fn restore(w: u32) -> u64 {
    let at = units(1);
    RESTORES.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push((at, w));
    at
}

/// Each lookup of a branch or a call through a register: its counters
/// (the target it took last, its runs to that same target again, its
/// runs), and whether it is a call.
static LOOKUPS: Mutex<Vec<(u64, bool)>> = Mutex::new(Vec::new());

/// Counters for a lookup of a branch (or a call, `call`) through a
/// register: their address ([`LOOKUPS`]).
pub(crate) fn lookup(call: bool) -> u64 {
    let at = units(3);
    LOOKUPS.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push((at, call));
    at
}

/// A way back after a call, counting its returns: its counter, the
/// origin of the block that makes the call, and the call's target if it is
/// direct.
struct Pad {
    at: u64,
    origin: usize,
    target: Option<u64>,
}

static PADS: Mutex<Vec<Pad>> = Mutex::new(Vec::new());
/// Cache lines flushed, by the page of the address flushed.
static FLUSHED: Mutex<Option<HashMap<u64, u64>>> = Mutex::new(None);

/// A counter for the returns to the way back after a call in a block of
/// `origin`, to `target` if direct: its address.
pub(crate) fn pad(origin: usize, target: Option<u64>) -> u64 {
    let at = units(1);
    PADS.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(Pad { at, origin, target });
    at
}

/// The program flushed the cache line at `addr`.
pub(crate) fn flushed(addr: u64) {
    if counting() {
        let page = addr & !(crate::page_size() - 1);
        let mut f = FLUSHED.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        *f.get_or_insert_with(HashMap::new).entry(page).or_default() += 1;
    }
}

/// A block, as the report counts it: its program address, origin, whether
/// it was made ahead, and its counters (its saved entry's and its other
/// entry's, if it counts).
pub(crate) struct Counted {
    pub g: u64,
    pub origin: usize,
    pub ahead: bool,
    pub counters: Option<u64>,
    /// Whether it is its program address's translation still, the
    /// program's words it holds, and its direct ways out by what leads
    /// there.
    pub live: bool,
    pub words: usize,
    pub leads: Vec<(u64, Lead)>,
}

/// What leads a direct way out to its target: an unconditional branch of
/// the program's (`b`) ahead within the words a block made at the
/// branching block's address could read, one elsewhere on the target's
/// page, one from another page, or anything else (a conditional branch,
/// the next instruction, a call).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lead {
    Ahead,
    Branch,
    BranchAway,
    Other,
}

/// Of the blocks in use, those an unconditional branch leads to (all of
/// them), and of those the ones nothing else leads to directly, by
/// [`Lead`] of their one branch: how many, their program's words, and
/// their runs (where blocks count them): each a branch from one block
/// into the next that a trace, the two made as one, would not take.
fn branched_to(blocks: &[Counted]) -> (u64, [(u64, u64, u64); 3]) {
    let mut by: HashMap<u64, [u32; 4]> = HashMap::new();
    for b in blocks.iter().filter(|b| b.live) {
        for &(to, lead) in &b.leads {
            by.entry(to).or_default()[lead as usize] += 1;
        }
    }
    let (mut all, mut only) = (0, [(0u64, 0u64, 0u64); 3]);
    for b in blocks.iter().filter(|b| b.live) {
        let Some(&leads) = by.get(&b.g) else { continue };
        let branches: u32 = leads[..3].iter().sum();
        if branches == 0 {
            continue;
        }
        all += 1;
        if branches == 1 && leads[Lead::Other as usize] == 0 {
            let k = leads.iter().position(|&n| n == 1).expect("one branch");
            only[k].0 += 1;
            only[k].1 += b.words as u64;
            only[k].2 += b.counters.map_or(0, |c| count(c) + count(c + 8));
        }
    }
    (all, only)
}

/// Whether the program's word `w` is one a translation changes: a system
/// call, a thread-pointer access, a use of `x18` (any word that may name
/// it), or a cache flush.
fn changed_by_translation(w: u32) -> bool {
    w & 0xffe0_001f == 0xd400_0001
        || w & !crate::rewrite::RT_MASK == crate::rewrite::MRS_TPIDR
        || w & !crate::rewrite::RT_MASK == crate::rewrite::MSR_TPIDR
        || crate::rewrite::is_ic_ivau(w)
        || crate::decode::may_use_x18(w)
}

/// The report: what was counted always, and, with `FWE_JIT_COUNT`, from
/// the blocks' counters (`blocks`, every block made; `is_file`, whether a
/// program address is code from a file).
pub(crate) fn report(blocks: &[Counted], is_file: impl Fn(u64) -> bool) -> String {
    let ms = |n: &AtomicU64| n.load(Ordering::Relaxed) / 1_000_000;
    let n = |n: &AtomicU64| n.load(Ordering::Relaxed);
    let mut out = format!(
        "blocks made {} {} ({} ms), {} {} ({} ms); {} with a second pass ({} words), {} of them \
         entered there, {} made again for it; {} made ahead",
        ORIGINS[FILE],
        n(&MADE[FILE]),
        ms(&MAKE_NS[FILE]),
        ORIGINS[GENERATED],
        n(&MADE[GENERATED]),
        ms(&MAKE_NS[GENERATED]),
        n(&SECOND),
        n(&SECOND_WORDS),
        n(&SECOND_USED),
        n(&SECOND_REMADE),
        n(&AHEAD),
    );
    out.push_str("; making a block, ns each step:");
    for (k, name) in STEPS.iter().enumerate() {
        let runs = n(&STEP_RUNS[k]);
        out.push_str(&format!(" {name} {}", n(&STEP_NS[k]) / runs.max(1)));
        out.push_str(if k + 1 < STEPS.len() { "," } else { "" });
    }
    out.push_str(&format!(
        "; taken from those kept {} {}, {} {} ({} ms), {} records read for them, {} found made \
         otherwise, {} files of them mapped ({} ms), {} generated made again where a past process \
         made them (kept)",
        ORIGINS[FILE],
        n(&TAKEN[FILE]),
        ORIGINS[GENERATED],
        n(&TAKEN[GENERATED]),
        ms(&TAKE_NS),
        n(&KEPT_READ),
        n(&KEPT_OTHER),
        n(&LOADED),
        ms(&LOAD_NS),
        n(&NOTED_AGAIN),
    ));
    let made = n(&MADE[FILE]) + n(&MADE[GENERATED]);
    out.push_str(&format!(
        "; {:.1} of the program's words a block; blocks end at {}",
        n(&WORDS) as f64 / made.max(1) as f64,
        ENDS.iter()
            .zip(&ENDED)
            .map(|(name, c)| format!("{name} {}", n(c)))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    let (to, [ahead, near, away]) = branched_to(blocks);
    out.push_str(&format!(
        "; blocks in use a branch leads to {to}, led to by nothing else directly: from close \
         behind {} ({} words), from elsewhere on their page {} ({} words), from another page {} \
         ({} words)",
        ahead.0, ahead.1, near.0, near.1, away.0, away.1
    ));
    if counting() {
        out.push_str(&format!(" (run {}, {} and {} times)", ahead.2, near.2, away.2));
    }
    if *SEEN_READ.get().unwrap_or(&false) {
        out.push_str(&format!(
            "; made before by another process: {} {} at the same address ({} by two or more), {} \
             elsewhere; {} {} ({}), {}",
            ORIGINS[FILE],
            n(&REPEATED[FILE]),
            n(&TWICE[FILE]),
            n(&MOVED[FILE]),
            ORIGINS[GENERATED],
            n(&REPEATED[GENERATED]),
            n(&TWICE[GENERATED]),
            n(&MOVED[GENERATED]),
        ));
    }
    if !counting() {
        return out;
    }
    // Runs, by origin, and the blocks that ran.
    let (mut runs, mut ran, mut second_runs) = ([0u64; 2], [0u64; 2], 0u64);
    let (mut ahead, mut ahead_ran) = (0u64, 0u64);
    let mut page_runs: HashMap<u64, u64> = HashMap::new();
    let page = crate::page_size();
    for b in blocks {
        let Some(c) = b.counters else { continue };
        let (first, other) = (count(c), count(c + 8));
        runs[b.origin] += first + other;
        second_runs += other;
        let did = first + other > 0;
        ran[b.origin] += u64::from(did);
        if b.ahead {
            ahead += 1;
            ahead_ran += u64::from(did);
        }
        if b.origin == GENERATED {
            *page_runs.entry(b.g & !(page - 1)).or_default() += first + other;
        }
    }
    out.push_str(&format!(
        "; counted: blocks run {} {} of {}, {} {} of {} ({} and {} runs; {} entered with the \
         program's own registers); made ahead {}, run {}",
        ORIGINS[FILE],
        ran[FILE],
        n(&MADE[FILE]),
        ORIGINS[GENERATED],
        ran[GENERATED],
        n(&MADE[GENERATED]),
        runs[FILE],
        runs[GENERATED],
        second_runs,
        ahead,
        ahead_ran,
    ));
    // The program's x16 and x17 taken back from their slots, by why, and
    // saved there again; those for other instructions by the instruction.
    let mut other: HashMap<u32, u64> = HashMap::new();
    for &(at, w) in RESTORES.lock().unwrap_or_else(std::sync::PoisonError::into_inner).iter() {
        *other.entry(w).or_default() += count(at);
    }
    let mut other: Vec<(u32, u64)> = other.into_iter().filter(|&(_, n)| n > 0).collect();
    other.sort_unstable_by_key(|&(w, n)| (std::cmp::Reverse(n), w));
    let most: Vec<String> = other.iter().take(8).map(|(w, n)| format!("{w:08x} {n}")).collect();
    out.push_str(&format!(
        "; x16 and x17 taken back {} times for an instruction naming them, {} for another \
         (most often: {}), saved again {} times",
        count(moves(RESTORE_NAMED)),
        other.iter().map(|&(_, n)| n).sum::<u64>(),
        most.join(", "),
        count(moves(SAVED_AGAIN)),
    ));
    // Lookups of branches and calls through a register: their runs, those
    // to the target taken there last, and the runs at sites that went
    // there at least 9 times in 10.
    for call in [false, true] {
        let (mut runs, mut same, mut steady) = (0, 0, 0);
        for &(at, c) in LOOKUPS.lock().unwrap_or_else(std::sync::PoisonError::into_inner).iter() {
            if c == call {
                let (s, r) = (count(at + 8), count(at + 16));
                runs += r;
                same += s;
                if 10 * s >= 9 * r {
                    steady += r;
                }
            }
        }
        out.push_str(&format!(
            "; {} through a register {runs} times, {same} of them to where the last went, {steady} \
             at sites that went there 9 times in 10",
            if call { "calls" } else { "branches" },
        ));
    }
    // Returns into each origin's code, by the call they come back from.
    let mut returns: HashMap<(usize, &str), u64> = HashMap::new();
    for p in PADS.lock().unwrap_or_else(std::sync::PoisonError::into_inner).iter() {
        let to = match p.target {
            Some(t) if is_file(t) => "a direct call into code from files",
            Some(_) => "a direct call into generated code",
            None => "a call through a register",
        };
        *returns.entry((p.origin, to)).or_default() += count(p.at);
    }
    let mut r: Vec<_> = returns.into_iter().collect();
    r.sort_unstable();
    out.push_str("; returns into code");
    for ((origin, to), k) in r {
        out.push_str(&format!(" {}, from {to}: {k};", ORIGINS[origin]));
    }
    // The pages of generated code that ran, and those a translation would
    // not change.
    let flushed = FLUSHED.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (mut clean, mut clean_runs, mut clean_flushed, mut all_runs) = (0u64, 0u64, 0u64, 0u64);
    for (&p, &k) in &page_runs {
        all_runs += k;
        let words = (p..p + page).step_by(4).map(crate::trap::read_host::<u32>);
        if words.clone().all(|w| w.is_some_and(|w| !changed_by_translation(w))) {
            clean += 1;
            clean_runs += k;
            clean_flushed += flushed.as_ref().and_then(|f| f.get(&p)).copied().unwrap_or(0);
        }
    }
    out.push_str(&format!(
        " generated code's pages {}, {clean} of them clean ({clean_runs} of {all_runs} runs, \
         {clean_flushed} cache lines flushed)",
        page_runs.len()
    ));
    out
}
