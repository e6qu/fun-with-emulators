//! User namespaces: the uid and gid maps, and the ids a process sees
//! through them.
//!
//! A process's credentials are kept as the initial namespace's ids (Linux's
//! kuids); what a process in a user namespace of fwe's sees is them mapped
//! down its namespaces' `uid_map` and `gid_map` (an id with no mapping is
//! the overflow id 65534), and what it sets is mapped back up (`EINVAL` for
//! one that has none). A new namespace's maps are empty until written,
//! once, through `/proc/<pid>/uid_map` and `gid_map`, with Linux's rules.
//! A capability held in a namespace reaches only it and the namespaces
//! below it ([`capable_in`]).

use crate::shared::{Data, Record};
use crate::snapshot::{Dec, Enc};
use fwe_abi::errno;
use std::sync::{Arc, Mutex};

/// The id an unmapped one shows as.
pub const OVERFLOW: u32 = 65534;

/// The most lines a map may have.
const MAX_EXTENTS: usize = 340;

/// One line of a map: `count` ids from `inside` are the parent's from
/// `outside`.
pub type Extent = (u32, u32, u32);

/// A user namespace.
#[derive(Clone, Default, Debug)]
pub struct UserNs {
    /// The namespace this one is inside, `None` for one inside the initial
    /// namespace.
    pub parent: Option<(Vec<u8>, u64)>,
    /// The (initial namespace's) effective uid of its maker.
    pub owner: u32,
    pub uid_map: Vec<Extent>,
    pub gid_map: Vec<Extent>,
    /// Whether `setgroups` is denied (`/proc/<pid>/setgroups` holds
    /// "deny").
    pub setgroups_deny: bool,
}

impl Data for UserNs {
    fn encode(&self, e: &mut Enc) {
        match &self.parent {
            Some((d, id)) => {
                e.bool(true);
                e.bytes(d);
                e.u64(*id);
            }
            None => e.bool(false),
        }
        e.u32(self.owner);
        for map in [&self.uid_map, &self.gid_map] {
            e.u64(map.len() as u64);
            for (a, b, c) in map {
                e.u32(*a);
                e.u32(*b);
                e.u32(*c);
            }
        }
        e.bool(self.setgroups_deny);
    }

    fn decode(d: &mut Dec) -> Self {
        let parent = if d.bool() { Some((d.bytes(), d.u64())) } else { None };
        let owner = d.u32();
        let mut maps = [Vec::new(), Vec::new()];
        for map in &mut maps {
            let n = d.count(12);
            *map = (0..n).map(|_| (d.u32(), d.u32(), d.u32())).collect();
        }
        let [uid_map, gid_map] = maps;
        UserNs { parent, owner, uid_map, gid_map, setgroups_deny: d.bool() }
    }
}

/// The process's user namespaces: its own, then each above it, up to (not
/// including) the initial one.
pub type Chain = Vec<Arc<Record<UserNs>>>;

pub(crate) static CURRENT: Mutex<Option<Arc<Chain>>> = Mutex::new(None);

/// Whether [`CURRENT`] holds any namespace: most processes are in none,
/// and a mapping of an id (every `stat` maps two) looks no further.
static NESTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The chain from `ns` up.
pub fn chain_from(ns: Option<Arc<Record<UserNs>>>) -> Chain {
    let mut out = Vec::new();
    let mut at = ns;
    while let Some(r) = at {
        let parent = r.get().parent.clone();
        out.push(r);
        at = parent.and_then(|(dir, id)| Record::join(&dir, id).ok().map(Arc::new));
    }
    out
}

/// Make `ns` (and those above it) the process's.
pub fn set_current(ns: Option<Arc<Record<UserNs>>>) {
    let chain = Arc::new(chain_from(ns));
    let mut current = CURRENT.lock().unwrap_or_else(|e| e.into_inner());
    NESTED.store(!chain.is_empty(), std::sync::atomic::Ordering::SeqCst);
    *current = Some(chain);
}

fn current() -> Arc<Chain> {
    CURRENT.lock().unwrap_or_else(|e| e.into_inner()).clone().unwrap_or_default()
}

/// The process's user namespaces: its own first (none: the initial one).
pub fn chain() -> Arc<Chain> {
    current()
}

/// Whether the process is in a user namespace of fwe's.
pub fn nested() -> bool {
    NESTED.load(std::sync::atomic::Ordering::SeqCst)
}

/// Whether the process may make a user namespace below its own: not from
/// inside a `chroot` (`chrooted`), which it could leave with the
/// capabilities the new namespace gives (`EPERM`).
pub fn may_make(chrooted: bool) -> Result<(), i32> {
    if chrooted { Err(errno::EPERM) } else { Ok(()) }
}

fn down(map: &[Extent], outside: u32) -> Option<u32> {
    map.iter()
        .find(|(_, o, c)| outside >= *o && outside - *o < *c)
        .map(|(i, o, _)| i + (outside - o))
}

fn up(map: &[Extent], inside: u32) -> Option<u32> {
    map.iter().find(|(i, _, c)| inside >= *i && inside - *i < *c).map(|(i, o, _)| o + (inside - i))
}

/// What the initial namespace's id `id` is in the process's namespace
/// (`gid` for a group id).
pub fn to_ns(id: u32, gid: bool) -> u32 {
    if !nested() {
        return id;
    }
    let chain = current();
    let mut v = id;
    for ns in chain.iter().rev() {
        let n = ns.get();
        let map = if gid { &n.gid_map } else { &n.uid_map };
        match down(map, v) {
            Some(x) => v = x,
            None => return OVERFLOW,
        }
    }
    v
}

/// The initial namespace's id for the process's namespace's id `id`, if it
/// has one.
pub fn from_ns(id: u32, gid: bool) -> Option<u32> {
    if !nested() {
        return Some(id);
    }
    let chain = current();
    let mut v = id;
    for ns in chain.iter() {
        let n = ns.get();
        let map = if gid { &n.gid_map } else { &n.uid_map };
        v = up(map, v)?;
    }
    Some(v)
}

/// Whether the initial namespace's id `id` has a mapping in the
/// process's namespace (`gid` for a group id): Linux's `kuid_has_mapping`.
pub fn mapped(id: u32, gid: bool) -> bool {
    mapped_through(&current(), id, gid)
}

fn mapped_through(chain: &Chain, id: u32, gid: bool) -> bool {
    let mut v = id;
    for ns in chain.iter().rev() {
        let n = ns.get();
        match down(if gid { &n.gid_map } else { &n.uid_map }, v) {
            Some(x) => v = x,
            None => return false,
        }
    }
    true
}

/// The directory of the process's user namespace's record (empty for the
/// initial one).
pub fn own_dir() -> Vec<u8> {
    current().first().map_or_else(Vec::new, |r| r.dir().to_vec())
}

/// The user namespace whose record is `dir`, joined once per process (a
/// joined record stays mapped for as long as the process lives).
fn joined(dir: &[u8]) -> Option<Arc<Record<UserNs>>> {
    static JOINED: Mutex<Vec<Arc<Record<UserNs>>>> = Mutex::new(Vec::new());
    if let Some(r) = current().iter().find(|r| r.dir() == dir) {
        return Some(r.clone());
    }
    let mut j = JOINED.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(r) = j.iter().find(|r| r.dir() == dir) {
        return Some(r.clone());
    }
    let r = Arc::new(Record::join(dir, 0).ok()?);
    j.push(r.clone());
    Some(r)
}

/// The parent of the user namespace whose record is `dir` (empty: the
/// initial one), `None` if there is no such namespace.
pub fn parent_dir(dir: &[u8]) -> Option<Vec<u8>> {
    let r = joined(dir)?;
    Some(r.get().parent.as_ref().map_or_else(Vec::new, |p| p.0.clone()))
}

/// Whether a process of this one's user namespace, with effective uid
/// `euid` (the initial namespace's) and `effective` holding the capability
/// asked about, has it in the user namespace whose record is `target`
/// (empty: the initial one): Linux's `cap_capable`. In its own namespace
/// by its effective set; in a namespace below its own made by its
/// effective user (its owner), every capability, and so in every namespace
/// below that; in any other (its parents', a sibling's) none.
pub fn capable_in(target: &[u8], euid: u32, effective: bool) -> bool {
    capable_from(&own_dir(), target, euid, effective)
}

/// [`capable_in`] for a process in the user namespace whose record is
/// `own` (another process's, `PTRACE_TRACEME` asks of its parent).
pub fn capable_of(own: &[u8], target: &[u8], euid: u32, effective: bool) -> bool {
    capable_from(own, target, euid, effective)
}

/// [`capable_in`] for a process in the user namespace whose record is
/// `own`.
fn capable_from(own: &[u8], target: &[u8], euid: u32, effective: bool) -> bool {
    let mut at = target.to_vec();

    // Namespaces nest at most 32 deep.
    for _ in 0..40 {
        if at == own {
            return effective;
        }
        if at.is_empty() {
            return false;
        }
        let Some(r) = joined(&at) else { return false };
        let ns = r.get();
        let parent = ns.parent.as_ref().map_or_else(Vec::new, |p| p.0.clone());
        if parent == own && ns.owner == euid {
            return true;
        }
        at = parent;
    }
    false
}

/// The initial namespace's ids of root (uid and gid 0) of the user
/// namespace whose record is `dir`, or the initial root's where it maps
/// none (Linux's `task_dump_owner`).
pub fn root_of(dir: &[u8]) -> (u32, u32) {
    if dir.is_empty() {
        return (0, 0);
    }
    let chain = chain_from(joined(dir));
    let up_through = |gid: bool| {
        let mut v = 0;
        for ns in chain.iter() {
            let n = ns.get();
            v = up(if gid { &n.gid_map } else { &n.uid_map }, v)?;
        }
        Some(v)
    };
    match (up_through(false), up_through(true)) {
        (Some(u), Some(g)) => (u, g),
        _ => (0, 0),
    }
}

/// The initial namespace's uids of root of the process's user namespace
/// and of each above it, the initial one's (0) last.
pub fn roots_above() -> Vec<u32> {
    let mut out: Vec<u32> = current().iter().map(|r| root_of(r.dir()).0).collect();
    out.push(0);
    out
}

/// Whether `setgroups` is allowed in the process's namespaces.
pub fn setgroups_allowed() -> bool {
    current().iter().all(|ns| !ns.get().setgroups_deny && !ns.get().gid_map.is_empty())
}

/// A map written to a namespace (`gid` for `gid_map`) as text, by a writer
/// that `privileged` (has `CAP_SETUID`/`CAP_SETGID`) or else may map only
/// its own (initial namespace's) id `own` (in its parent's terms `own_ns`).
pub fn write_map(
    ns: &Record<UserNs>,
    gid: bool,
    text: &[u8],
    privileged: bool,
    own_ns: u32,
) -> Result<(), i32> {
    let text = std::str::from_utf8(text).map_err(|_| errno::EINVAL)?;
    let mut map: Vec<Extent> = Vec::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let w: Vec<&str> = line.split_whitespace().collect();
        let [i, o, c] = w[..] else { return Err(errno::EINVAL) };
        let parse = |s: &str| s.parse::<u32>().map_err(|_| errno::EINVAL);
        let (i, o, c) = (parse(i)?, parse(o)?, parse(c)?);
        // Linux takes ids up to 2^32 - 2: an extent may not reach 2^32 - 1.
        if c == 0 || i.checked_add(c).is_none() || o.checked_add(c).is_none() {
            return Err(errno::EINVAL);
        }
        let (iw, ow, cw) = (u64::from(i), u64::from(o), u64::from(c));
        let overlaps = |(a, b, n): &Extent| {
            let (a, b, n) = (u64::from(*a), u64::from(*b), u64::from(*n));
            (iw < a + n && a < iw + cw) || (ow < b + n && b < ow + cw)
        };
        if map.iter().any(overlaps) {
            return Err(errno::EINVAL);
        }
        map.push((i, o, c));
    }
    if map.is_empty() || map.len() > MAX_EXTENTS {
        return Err(errno::EINVAL);
    }
    // Each extent's ids must be the parent namespace's, all within one
    // extent of its map (Linux's `map_id_range_down` of the parent's map,
    // for every writer): the initial namespace has them all.
    if let Some((dir, _)) = &ns.get().parent {
        let parent = joined(dir).ok_or(errno::EPERM)?;
        let p = parent.get();
        let pmap = if gid { &p.gid_map } else { &p.uid_map };
        if !map.iter().all(|&(_, o, c)| within_one(pmap, o, c)) {
            return Err(errno::EPERM);
        }
    }
    ns.update(|n| {
        let current = if gid { &n.gid_map } else { &n.uid_map };
        if !current.is_empty() {
            return Err(errno::EPERM);
        }
        // Without the capability, only one's own id, once, and for groups
        // only with setgroups denied.
        let own_only = map.len() == 1 && map[0].1 == own_ns && map[0].2 == 1;
        if !privileged && (!own_only || gid && !n.setgroups_deny) {
            return Err(errno::EPERM);
        }
        if gid {
            n.gid_map = map;
        } else {
            n.uid_map = map;
        }
        Ok(())
    })
}

/// Whether ids `first` to `first + count - 1` of a namespace are all inside
/// one extent of its `map`.
fn within_one(map: &[Extent], first: u32, count: u32) -> bool {
    let (first, count) = (u64::from(first), u64::from(count));
    map.iter().any(|&(i, _, c)| {
        let (i, c) = (u64::from(i), u64::from(c));
        first >= i && first + count <= i + c
    })
}

/// `setgroups` written to a namespace: "allow" or "deny", before its
/// `gid_map` is.
pub fn write_setgroups(ns: &Record<UserNs>, text: &[u8]) -> Result<(), i32> {
    let deny = match std::str::from_utf8(text).map_err(|_| errno::EINVAL)?.trim() {
        "deny" => true,
        "allow" => false,
        _ => return Err(errno::EINVAL),
    };
    ns.update(|n| {
        if !n.gid_map.is_empty() {
            return Err(errno::EPERM);
        }
        n.setgroups_deny = deny;
        Ok(())
    })
}

/// A map as `/proc/<pid>/uid_map` shows it.
pub fn show_map(map: &[Extent]) -> Vec<u8> {
    map.iter()
        .map(|(i, o, c)| format!("{i:>10} {o:>10} {c:>10}\n"))
        .collect::<String>()
        .into_bytes()
}

/// A write of `len` bytes, `data` the first of them, to `fd`: for a map
/// file of `/proc/<pid>` opened for writing, what the write does (`Some`
/// result; see [`crate::specialwrite`]).
pub fn try_write(fd: i32, data: &[u8], len: u64) -> Option<i64> {
    let Some(crate::fdmarks::Mark::ProcMap { host, which, privileged, own }) =
        crate::fdmarks::marked(fd)
    else {
        return None;
    };
    let data = &data[..data.len().min(4096)];
    let rec = crate::procreg::read(host).and_then(|r| crate::procpid::user_record(&r.ns));
    let Some(ns) = rec else {
        // The initial namespace's maps are fixed.
        return Some(fwe_abi::err(errno::EPERM));
    };
    let r = match which {
        0 => write_map(&ns, false, data, privileged, own),
        1 => write_map(&ns, true, data, privileged, own),
        _ => write_setgroups(&ns, data),
    };
    Some(match r {
        Ok(()) => len as i64,
        Err(e) => fwe_abi::err(e),
    })
}

/// The opener's standing for a map of the user namespace record `target`
/// (`gid` for `gid_map`): whether it is privileged over it (has the
/// capability and is outside it), and its own id in the map's parent's
/// terms.
pub fn standing(target: &Record<UserNs>, kid: u32, gid: bool, has_cap: bool) -> (bool, u32) {
    let inside = current().first().is_some_and(|r| r.dir() == target.dir());
    let parent =
        target.get().parent.clone().and_then(|(d, id)| Record::join(&d, id).ok().map(Arc::new));
    // The id in the parent's terms: down the parent's chain.
    let chain = chain_from(parent);
    let mut v = kid;
    for ns in chain.iter().rev() {
        let n = ns.get();
        match down(if gid { &n.gid_map } else { &n.uid_map }, v) {
            Some(x) => v = x,
            None => {
                v = OVERFLOW;
                break;
            }
        }
    }
    (has_cap && !inside, v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_both_ways() {
        let map = vec![(0, 1000, 1), (1, 100000, 65536)];
        assert_eq!(down(&map, 1000), Some(0));
        assert_eq!(down(&map, 100005), Some(6));
        assert_eq!(down(&map, 5), None);
        assert_eq!(up(&map, 0), Some(1000));
        assert_eq!(up(&map, 65536), Some(165535));
        assert_eq!(up(&map, 65537), None);
        assert_eq!(show_map(&map[..1]), b"         0       1000          1\n");
    }

    /// A map written to a namespace inside another names only ids its
    /// parent has, each extent within one of the parent's (`EPERM`), even
    /// for a privileged writer; inside the initial namespace, any.
    #[test]
    fn a_map_is_checked_against_the_parents() {
        let parent = Record::fresh(
            "user",
            UserNs {
                owner: 1000,
                uid_map: vec![(0, 1000, 1), (1, 100000, 10)],
                ..Default::default()
            },
        )
        .unwrap();
        let child = || {
            let parent = Some((parent.dir().to_vec(), 0));
            Record::fresh("user", UserNs { parent, owner: 1000, ..Default::default() }).unwrap()
        };
        // Within one of the parent's extents, or several each within one.
        assert_eq!(write_map(&child(), false, b"0 0 1\n", true, 0), Ok(()));
        assert_eq!(write_map(&child(), false, b"0 1 10\n", true, 0), Ok(()));
        assert_eq!(write_map(&child(), false, b"0 0 1\n1 1 10\n", true, 0), Ok(()));
        // Across two extents, past the end, or an id the parent lacks.
        assert_eq!(write_map(&child(), false, b"0 0 2\n", true, 0), Err(errno::EPERM));
        assert_eq!(write_map(&child(), false, b"0 5 10\n", true, 0), Err(errno::EPERM));
        assert_eq!(write_map(&child(), false, b"0 1000 1\n", true, 0), Err(errno::EPERM));
        // The parent has no gid map yet: no group of it can be named.
        assert_eq!(write_map(&child(), true, b"0 0 1\n", true, 0), Err(errno::EPERM));
        // Unprivileged, its own id unmapped in the parent's terms: refused.
        assert_eq!(write_map(&child(), false, b"0 65534 1\n", false, 65534), Err(errno::EPERM));
        // Inside the initial namespace: any ids.
        let top = Record::fresh("user", UserNs { owner: 0, ..Default::default() }).unwrap();
        assert_eq!(write_map(&top, false, b"0 100000 65536\n", true, 0), Ok(()));
    }

    #[test]
    fn capabilities_reach_own_and_owned_namespaces_only() {
        let fresh = |parent: &[u8], owner| {
            let parent = (!parent.is_empty()).then(|| (parent.to_vec(), 0));
            Record::fresh("user", UserNs { parent, owner, ..Default::default() }).unwrap()
        };
        // User 1000's namespace, one it made inside that, and user 2000's.
        let a = fresh(b"", 1000);
        let b = fresh(a.dir(), 1000);
        let c = fresh(b"", 2000);
        let init: &[u8] = b"";
        // In the initial namespace: by the effective set there, and in
        // every namespace below it.
        assert!(capable_from(init, init, 0, true) && !capable_from(init, init, 0, false));
        assert!(capable_from(init, c.dir(), 0, true));
        // A user without the capability has every one in a namespace it
        // made, and below it; not in another user's.
        assert!(capable_from(init, a.dir(), 1000, false));
        assert!(capable_from(init, b.dir(), 1000, false));
        assert!(!capable_from(init, c.dir(), 1000, false));
        // Inside its namespace: its effective set there, nothing in the
        // initial namespace or a sibling, whatever its set holds.
        assert!(capable_from(a.dir(), a.dir(), 1000, true));
        assert!(!capable_from(a.dir(), a.dir(), 1000, false));
        assert!(!capable_from(a.dir(), init, 1000, true));
        assert!(!capable_from(a.dir(), c.dir(), 1000, true));
        // A namespace below made by another user: by the set it has in
        // its own namespace above it.
        assert!(capable_from(a.dir(), b.dir(), 5000, true));
        assert!(!capable_from(a.dir(), b.dir(), 5000, false));
        assert!(capable_from(a.dir(), b.dir(), 1000, false));
    }
}
