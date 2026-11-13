//! Keys and keyrings, as Linux's key retention service keeps them
//! (`add_key`, `request_key`, `keyctl`).
//!
//! Every key is kernel-wide, so they are kept in one record every fwe
//! process shares (a [`Store`]): each key's type, description, owner,
//! permissions, state, expiry and payload, and each keyring's links and
//! restriction. With them the keyrings each process holds (its thread,
//! process and session keyrings, by host pid and start time) and each
//! user's (user, user-session and persistent keyrings), from which keys
//! are reached: one that no keyring links and no process holds goes, as do
//! invalidated keys at once and revoked or expired ones after
//! `kernel.keys.gc_delay` seconds. A call reads and changes the record under
//! its lock, so what it sees is whole.
//!
//! A key is possessed by a process when its thread, process or session
//! keyring reaches it through keyrings the process may search; possession
//! adds a key's possessor permissions to the user's, group's or others'.
//! Root bypasses no key permission (as on Linux), but `CAP_SYS_ADMIN`
//! changes owners and permissions.
//!
//! The key types: `keyring`, `user`, `logon`, `big_key`, `dns_resolver`,
//! `asymmetric` (X.509 certificates and PKCS#8 RSA keys) and `encrypted`,
//! whose cryptography is [`crate::keycrypto`]'s. `request_key` finds a key
//! or, given callout information, constructs one: with no `/sbin/request-key`
//! helper to instantiate it, the key is negated for a minute, as Linux leaves
//! a key whose helper failed.

use crate::shared::{Data, Record};
use crate::snapshot::{Dec, Enc};
use crate::{Kernel, Platform, guest, uaccess};
use fwe_abi::keyctl::*;
use fwe_abi::{err, errno};
use std::collections::BTreeMap;

/// Key state flags.
const NEGATIVE: u32 = 1;
const REVOKED: u32 = 2;
const INVALIDATED: u32 = 4;
/// A user's own keyring (not found by name, not joined).
const UID_KEYRING: u32 = 8;
/// Charged to its owner's quota.
const IN_QUOTA: u32 = 16;
/// A keyring `CAP_SYS_ADMIN` may clear, and a key it may invalidate, without
/// the permission (the persistent keyrings).
const ROOT_CAN_CLEAR: u32 = 32;

/// How long a key whose construction failed stays negative.
const NEGATIVE_TIMEOUT: u64 = 60;
/// What each link in a keyring costs its owner's quota.
const LINK_BYTES: u64 = 4;
/// The deepest nesting of keyrings a search descends.
const MAX_DEPTH: usize = 6;
/// The largest payload `add_key` takes.
const MAX_PAYLOAD: usize = 1024 * 1024 - 1;
/// The largest payload `KEYCTL_UPDATE` takes (a page).
const PAGE: usize = 4096;
/// The longest description (a page, with its NUL).
const MAX_DESC: usize = 4095;
/// The kernel's `INVALID_GID` (a user keyring has no group).
const NO_ID: u32 = u32::MAX;

/// A keyring's restriction on what may be linked into it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Restrict {
    None,
    /// Nothing at all.
    RejectAll,
    /// Asymmetric keys signed by a key of the builtin (and with
    /// `secondary`, the secondary) trusted keyrings, which are empty here.
    Builtin {
        secondary: bool,
    },
    /// Asymmetric keys signed by key `0` (or a key in keyring `0`), and
    /// with `chain` by a key in the restricted keyring itself.
    KeyOrKeyring(i32, bool),
}

/// One key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key {
    pub serial: i32,
    pub kind: String,
    pub desc: Vec<u8>,
    /// Owner, as ids of the initial user namespace.
    pub uid: u32,
    pub gid: u32,
    pub perm: u32,
    pub flags: u32,
    /// When it expires, in seconds since the epoch (0: never).
    pub expiry: u64,
    /// When it was revoked (0: not), for collection.
    pub revoked_at: u64,
    /// The error a negative key gives.
    pub reject: i32,
    /// The type's payload (an asymmetric or encrypted key's encoded form).
    pub payload: Vec<u8>,
    /// A keyring's links, in the order made.
    pub links: Vec<i32>,
    pub restrict: Restrict,
    /// Bytes charged to the owner's quota.
    pub quota: u32,
    /// The user namespace it was made in (its record's directory; empty
    /// for the initial one), where a keyring is found by name.
    pub ns: Vec<u8>,
}

impl Key {
    fn is_keyring(&self) -> bool {
        self.kind == "keyring"
    }

    fn expired(&self, now: u64) -> bool {
        self.expiry != 0 && self.expiry <= now
    }

    pub fn negative(&self) -> bool {
        self.flags & NEGATIVE != 0
    }

    /// The error using it gives, if it is not usable (Linux's
    /// `key_validate`).
    fn invalid(&self, now: u64) -> Option<i32> {
        if self.flags & INVALIDATED != 0 {
            Some(errno::ENOKEY)
        } else if self.flags & REVOKED != 0 {
            Some(errno::EKEYREVOKED)
        } else if self.expired(now) {
            Some(errno::EKEYEXPIRED)
        } else {
            None
        }
    }
}

/// The keyrings a process holds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Holder {
    pub pid: i32,
    pub start: u64,
    /// Thread keyrings, by guest thread id.
    pub threads: Vec<(i32, i32)>,
    pub process: i32,
    pub session: i32,
    /// `KEYCTL_SET_REQKEY_KEYRING`'s choice.
    pub reqkey: i32,
}

/// A user's keyrings (0: not made yet).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UserRings {
    pub uid: u32,
    pub user: i32,
    pub session: i32,
    pub persistent: i32,
}

/// Every key, and who holds what.
#[derive(Clone, Debug, Default)]
pub struct Store {
    pub keys: BTreeMap<i32, Key>,
    pub holders: Vec<Holder>,
    pub users: Vec<UserRings>,
    /// A change was made, so the record is written back (never kept).
    pub touched: bool,
}

impl Data for Store {
    fn encode(&self, e: &mut Enc) {
        e.u64(self.keys.len() as u64);
        for k in self.keys.values() {
            e.i32(k.serial);
            e.bytes(k.kind.as_bytes());
            e.bytes(&k.desc);
            e.u32(k.uid);
            e.u32(k.gid);
            e.u32(k.perm);
            e.u32(k.flags);
            e.u64(k.expiry);
            e.u64(k.revoked_at);
            e.i32(k.reject);
            e.bytes(&k.payload);
            e.u64(k.links.len() as u64);
            for l in &k.links {
                e.i32(*l);
            }
            match k.restrict {
                Restrict::None => e.u8(0),
                Restrict::RejectAll => e.u8(1),
                Restrict::Builtin { secondary } => {
                    e.u8(2);
                    e.bool(secondary);
                }
                Restrict::KeyOrKeyring(id, chain) => {
                    e.u8(3);
                    e.i32(id);
                    e.bool(chain);
                }
            }
            e.u32(k.quota);
            e.bytes(&k.ns);
        }
        e.u64(self.holders.len() as u64);
        for h in &self.holders {
            e.i32(h.pid);
            e.u64(h.start);
            e.u64(h.threads.len() as u64);
            for (t, r) in &h.threads {
                e.i32(*t);
                e.i32(*r);
            }
            e.i32(h.process);
            e.i32(h.session);
            e.i32(h.reqkey);
        }
        e.u64(self.users.len() as u64);
        for u in &self.users {
            e.u32(u.uid);
            e.i32(u.user);
            e.i32(u.session);
            e.i32(u.persistent);
        }
    }

    fn decode(d: &mut Dec) -> Self {
        let mut s = Store::default();
        for _ in 0..d.count(48) {
            let serial = d.i32();
            let kind = String::from_utf8_lossy(&d.bytes()).into_owned();
            let desc = d.bytes();
            let (uid, gid, perm, flags) = (d.u32(), d.u32(), d.u32(), d.u32());
            let (expiry, revoked_at, reject) = (d.u64(), d.u64(), d.i32());
            let payload = d.bytes();
            let links = (0..d.count(4)).map(|_| d.i32()).collect();
            let restrict = match d.u8() {
                1 => Restrict::RejectAll,
                2 => Restrict::Builtin { secondary: d.bool() },
                3 => Restrict::KeyOrKeyring(d.i32(), d.bool()),
                _ => Restrict::None,
            };
            let quota = d.u32();
            let ns = d.bytes();
            let k = Key {
                serial,
                kind,
                desc,
                uid,
                gid,
                perm,
                flags,
                expiry,
                revoked_at,
                reject,
                payload,
                links,
                restrict,
                quota,
                ns,
            };
            s.keys.insert(serial, k);
        }
        for _ in 0..d.count(28) {
            let (pid, start) = (d.i32(), d.u64());
            let threads = (0..d.count(8)).map(|_| (d.i32(), d.i32())).collect();
            let (process, session, reqkey) = (d.i32(), d.i32(), d.i32());
            s.holders.push(Holder { pid, start, threads, process, session, reqkey });
        }
        for _ in 0..d.count(16) {
            s.users.push(UserRings {
                uid: d.u32(),
                user: d.i32(),
                session: d.i32(),
                persistent: d.i32(),
            });
        }
        s
    }
}

/// The shared record, once this process has opened it.
static STORE: std::sync::OnceLock<Option<Record<Store>>> = std::sync::OnceLock::new();

/// The shared record.
fn store() -> Option<&'static Record<Store>> {
    STORE.get_or_init(|| Record::named("keys", 0, Store::default).ok()).as_ref()
}

/// The shared record, if any process has made it: so a fork or exec of a
/// program that never used a key costs only a look.
fn existing() -> Option<&'static Record<Store>> {
    use std::os::unix::ffi::OsStrExt;
    let mut dir = crate::fs::shm::user_dir().ok()?;
    dir.extend_from_slice(format!("/v{}-keys", crate::shared::FORMAT).as_bytes());
    std::fs::metadata(std::ffi::OsStr::from_bytes(&dir)).ok()?;
    store()
}

/// Seconds since the epoch.
fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// A `kernel.keys.*` sysctl.
fn sysctl(name: &str) -> u64 {
    crate::sysctl::number(format!("kernel/keys/{name}").as_bytes()).unwrap_or(0).max(0) as u64
}

/// Who calls, as the keys see it.
#[derive(Clone, Debug)]
pub struct Caller {
    pub pid: i32,
    pub start: u64,
    pub tid: i32,
    /// File-system ids, in the initial user namespace.
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
    pub admin: bool,
    pub setuid: bool,
    /// The user namespace (its record's directory; empty: the initial one).
    pub userns: Vec<u8>,
}

/// This process's identity: host pid and start time.
fn me() -> (i32, u64) {
    // SAFETY: getpid cannot fail.
    let pid = unsafe { libc::getpid() };
    (pid, crate::procreg::host_info(pid).map_or(0, |i| i.0))
}

/// How a key id is looked up (Linux's `KEY_LOOKUP_*`): whether a missing
/// special keyring is made, and whether a key whose state makes it unusable
/// (negative; with `partial`, revoked or expired instead) is still found.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Look {
    create: bool,
    partial: bool,
}

impl Look {
    const PLAIN: Look = Look { create: false, partial: false };
    const CREATE: Look = Look { create: true, partial: false };
    const PARTIAL: Look = Look { create: false, partial: true };
    const CREATE_PARTIAL: Look = Look { create: true, partial: true };
}

impl Store {
    /// What `c` holds. A fork child that has not used its keyrings yet,
    /// before its parent has written what it holds, holds what the parent
    /// did as it forked ([`INHERIT`]), as [`Store::holder_mut`] would make
    /// it.
    fn holder(&self, c: &Caller) -> Option<std::borrow::Cow<'_, Holder>> {
        if let Some(h) = self.holders.iter().find(|h| h.pid == c.pid && h.start == c.start) {
            return Some(std::borrow::Cow::Borrowed(h));
        }
        // SAFETY: getpid cannot fail.
        if c.pid != unsafe { libc::getpid() } {
            return None;
        }
        match *INHERIT.lock().unwrap_or_else(|e| e.into_inner()) {
            Some((parent, session, reqkey)) if parent != c.pid => {
                Some(std::borrow::Cow::Owned(Holder {
                    pid: c.pid,
                    start: c.start,
                    session,
                    reqkey,
                    ..Holder::default()
                }))
            }
            _ => None,
        }
    }

    fn holder_mut(&mut self, c: &Caller) -> &mut Holder {
        self.touched = true;
        if let Some(i) = self.holders.iter().position(|h| h.pid == c.pid && h.start == c.start) {
            return &mut self.holders[i];
        }
        // A fork child's first: its parent's session and request default,
        // as they were when it forked.
        let (session, reqkey) = match *INHERIT.lock().unwrap_or_else(|e| e.into_inner()) {
            Some((parent, session, reqkey)) if parent != c.pid => (session, reqkey),
            _ => (0, 0),
        };
        self.holders.push(Holder {
            pid: c.pid,
            start: c.start,
            session,
            reqkey,
            ..Holder::default()
        });
        self.holders.last_mut().unwrap()
    }

    /// A fresh serial: random and positive, as Linux's.
    fn serial(&self) -> i32 {
        loop {
            let mut b = [0u8; 4];
            crate::host::fill_random(&mut b);
            let s = (u32::from_ne_bytes(b) & 0x7fff_ffff) as i32;
            if s >= 3 && !self.keys.contains_key(&s) {
                return s;
            }
        }
    }

    /// The keys user `uid` owns, and their bytes, charged to its quota: a
    /// keyring's description and its links, another key's description and
    /// what its type charges for its payload.
    fn usage(&self, uid: u32) -> (u64, u64) {
        self.keys.values().filter(|k| k.uid == uid && k.flags & IN_QUOTA != 0).fold(
            (0, 0),
            |(n, b), k| {
                let bytes = if k.is_keyring() {
                    k.desc.len() as u64 + 1 + LINK_BYTES * k.links.len() as u64
                } else {
                    k.quota as u64
                };
                (n + 1, b + bytes)
            },
        )
    }

    /// User `uid`'s quota limits: keys and bytes.
    fn limits(uid: u32) -> (u64, u64) {
        if uid == 0 {
            (sysctl("root_maxkeys"), sysctl("root_maxbytes"))
        } else {
            (sysctl("maxkeys"), sysctl("maxbytes"))
        }
    }

    /// Whether `uid` may own `more` bytes more (and a key more, if `key`).
    fn quota_ok(&self, uid: u32, key: bool, more: u64) -> bool {
        let (n, b) = self.usage(uid);
        let (max_n, max_b) = Self::limits(uid);
        (!key || n < max_n) && b + more <= max_b
    }

    /// A new key, not linked anywhere. `overrun` lets it past the quota
    /// (the keyrings a process or session gets).
    #[allow(clippy::too_many_arguments)]
    fn alloc(
        &mut self,
        kind: &str,
        desc: &[u8],
        uid: u32,
        gid: u32,
        perm: u32,
        flags: u32,
        payload: Vec<u8>,
        overrun: bool,
    ) -> Result<i32, i32> {
        let quota = (desc.len() + 1 + crate::keytypes::charge(kind, &payload)) as u32;
        if !overrun && uid != NO_ID && !self.quota_ok(uid, true, quota as u64) {
            return Err(errno::EDQUOT);
        }
        self.touched = true;
        let serial = self.serial();
        self.keys.insert(
            serial,
            Key {
                serial,
                kind: kind.into(),
                desc: desc.to_vec(),
                uid,
                gid,
                perm,
                flags: flags | IN_QUOTA,
                expiry: 0,
                revoked_at: 0,
                reject: 0,
                payload,
                links: Vec::new(),
                restrict: Restrict::None,
                quota,
                ns: Vec::new(),
            },
        );
        Ok(serial)
    }

    /// A new keyring for the caller, as the kernel makes one for a process.
    fn new_ring(&mut self, c: &Caller, desc: &[u8], perm: u32) -> Result<i32, i32> {
        let r = self.alloc("keyring", desc, c.uid, c.gid, perm, 0, Vec::new(), true)?;
        self.keys.get_mut(&r).unwrap().ns = c.userns.clone();
        Ok(r)
    }

    /// User `uid`'s keyrings, made if missing: the user keyring and the
    /// user-session keyring that links it.
    fn user_rings(&mut self, uid: u32) -> UserRings {
        let i = match self.users.iter().position(|u| u.uid == uid) {
            Some(i) => i,
            None => {
                self.users.push(UserRings { uid, ..UserRings::default() });
                self.users.len() - 1
            }
        };
        let perm = ((KEY_ALL & !KEY_SETATTR) << KEY_POS_SHIFT) | (KEY_ALL << KEY_USR_SHIFT);
        if self.users[i].user == 0 || !self.keys.contains_key(&self.users[i].user) {
            let desc = format!("_uid.{uid}");
            let r = self
                .alloc("keyring", desc.as_bytes(), uid, NO_ID, perm, UID_KEYRING, Vec::new(), true)
                .unwrap_or(0);
            self.users[i].user = r;
        }
        if self.users[i].session == 0 || !self.keys.contains_key(&self.users[i].session) {
            let desc = format!("_uid_ses.{uid}");
            let r = self
                .alloc("keyring", desc.as_bytes(), uid, NO_ID, perm, UID_KEYRING, Vec::new(), true)
                .unwrap_or(0);
            let user = self.users[i].user;
            if let Some(k) = self.keys.get_mut(&r) {
                k.links.push(user);
            }
            self.users[i].session = r;
        }
        self.users[i].clone()
    }

    /// The caller's session keyring: its own, or its user's session
    /// keyring.
    fn session_of(&self, c: &Caller) -> i32 {
        let own = self.holder(c).map_or(0, |h| h.session);
        if own != 0 && self.live(own) {
            return own;
        }
        self.users.iter().find(|u| u.uid == c.uid).map_or(0, |u| u.session)
    }

    fn thread_of(&self, c: &Caller) -> i32 {
        self.holder(c)
            .and_then(|h| h.threads.iter().find(|(t, _)| *t == c.tid).map(|&(_, r)| r))
            .unwrap_or(0)
            .max(0)
    }

    fn process_of(&self, c: &Caller) -> i32 {
        self.holder(c).map_or(0, |h| h.process)
    }

    /// Whether key `id` exists and is not invalidated.
    fn live(&self, id: i32) -> bool {
        self.keys.get(&id).is_some_and(|k| k.flags & INVALIDATED == 0)
    }

    /// The permission bits key `k` grants the caller, possessed or not.
    fn granted(k: &Key, c: &Caller, possessed: bool) -> u32 {
        let mut p = if k.uid == c.uid {
            k.perm >> KEY_USR_SHIFT
        } else if k.gid != NO_ID && (k.gid == c.gid || c.groups.contains(&k.gid)) {
            k.perm >> KEY_GRP_SHIFT
        } else {
            k.perm
        } & KEY_ALL;
        if possessed {
            p |= (k.perm >> KEY_POS_SHIFT) & KEY_ALL;
        }
        p
    }

    /// The keys the caller possesses: those its thread, process and session
    /// keyrings reach through keyrings it may search, each searchable
    /// itself.
    fn possessed(&self, c: &Caller) -> Vec<i32> {
        let roots = [self.thread_of(c), self.process_of(c), self.session_of(c)];
        let mut out: Vec<i32> = Vec::new();
        let mut frontier: Vec<(i32, usize)> = Vec::new();
        for r in roots {
            if r != 0 && self.live(r) && !out.contains(&r) {
                out.push(r);
                frontier.push((r, 1));
            }
        }
        let now = now();
        while let Some((r, depth)) = frontier.pop() {
            let Some(ring) = self.keys.get(&r) else { continue };
            if !ring.is_keyring()
                || Self::granted(ring, c, true) & KEY_SEARCH == 0
                || ring.invalid(now).is_some()
            {
                continue;
            }
            for l in &ring.links {
                let Some(k) = self.keys.get(l) else { continue };
                if out.contains(l) || Self::granted(k, c, true) & KEY_SEARCH == 0 {
                    continue;
                }
                out.push(*l);
                if k.is_keyring() && depth < MAX_DEPTH {
                    frontier.push((*l, depth + 1));
                }
            }
        }
        out
    }

    /// Resolve key id `id` for the caller (Linux's `lookup_user_key`): a
    /// special keyring (made if missing and `look` allows), or a key. With
    /// `need`, the caller must have those permissions (`EACCES`). Returns
    /// the serial and whether the caller possesses it.
    fn lookup(&mut self, c: &Caller, id: i32, look: Look, need: u32) -> Result<(i32, bool), i32> {
        let serial = match id {
            KEY_SPEC_THREAD_KEYRING => {
                let mut r = self.thread_of(c);
                if r == 0 || !self.live(r) {
                    if !look.create {
                        return Err(errno::ENOKEY);
                    }
                    let perm = (KEY_ALL << KEY_POS_SHIFT) | (KEY_VIEW << KEY_USR_SHIFT);
                    r = self.new_ring(c, b"_tid", perm)?;
                    let tid = c.tid;
                    let h = self.holder_mut(c);
                    h.threads.retain(|(t, _)| *t != tid);
                    h.threads.push((tid, r));
                }
                r
            }
            KEY_SPEC_PROCESS_KEYRING => {
                let mut r = self.process_of(c);
                if r == 0 || !self.live(r) {
                    if !look.create {
                        return Err(errno::ENOKEY);
                    }
                    let perm = (KEY_ALL << KEY_POS_SHIFT) | (KEY_VIEW << KEY_USR_SHIFT);
                    r = self.new_ring(c, b"_pid", perm)?;
                    self.holder_mut(c).process = r;
                }
                r
            }
            KEY_SPEC_SESSION_KEYRING => {
                let own = self.holder(c).map_or(0, |h| h.session);
                let user_session =
                    self.users.iter().find(|u| u.uid == c.uid).map_or(0, |u| u.session);
                if own != 0 && self.live(own) && !(look.create && own == user_session) {
                    own
                } else if look.create {
                    // None of its own (or the user's): a new one, joined.
                    self.join(c, None)?
                } else {
                    // The user's session keyring becomes the session's.
                    let u = self.user_rings(c.uid);
                    self.holder_mut(c).session = u.session;
                    u.session
                }
            }
            KEY_SPEC_USER_KEYRING => self.user_rings(c.uid).user,
            KEY_SPEC_USER_SESSION_KEYRING => self.user_rings(c.uid).session,
            KEY_SPEC_GROUP_KEYRING => return Err(errno::EINVAL),
            KEY_SPEC_REQKEY_AUTH_KEY | KEY_SPEC_REQUESTOR_KEYRING => return Err(errno::ENOKEY),
            id if id < 1 => return Err(errno::EINVAL),
            id => {
                if !self.live(id) {
                    return Err(errno::ENOKEY);
                }
                id
            }
        };
        let possessed = id < 0 || self.possessed(c).contains(&serial);
        if need != 0 {
            let k = &self.keys[&serial];
            // A negative key is no use but to a partial lookup, which
            // takes a revoked or expired key as unusable instead.
            if !look.partial && k.negative() {
                return Err(if k.reject != 0 { k.reject } else { errno::ENOKEY });
            }
            if look.partial
                && let Some(e) = k.invalid(now())
            {
                return Err(e);
            }
            if Self::granted(k, c, possessed) & need != need {
                return Err(errno::EACCES);
            }
        }
        Ok((serial, possessed))
    }

    /// Join a session keyring: a new anonymous one (`name` none), or the
    /// keyring named `name` the caller may search, made if there is none.
    fn join(&mut self, c: &Caller, name: Option<&[u8]>) -> Result<i32, i32> {
        // An anonymous one is the process's own, past the quota; a named
        // one may be joined by others, and is charged.
        let anon = (KEY_ALL << KEY_POS_SHIFT) | ((KEY_VIEW | KEY_READ) << KEY_USR_SHIFT);
        let named = anon | (KEY_LINK << KEY_USR_SHIFT);
        let r = match name {
            None => self.new_ring(c, b"_ses", anon)?,
            Some(n) if n.first() == Some(&b'.') => return Err(errno::EPERM),
            Some(n) => {
                let found = self
                    .keys
                    .values()
                    .filter(|k| {
                        k.is_keyring()
                            && k.desc == n
                            && k.flags & (UID_KEYRING | INVALIDATED | REVOKED) == 0
                            && k.ns == c.userns
                    })
                    .find(|k| Self::granted(k, c, false) & KEY_SEARCH != 0)
                    .map(|k| k.serial);
                match found {
                    Some(r) => r,
                    None => {
                        let r =
                            self.alloc("keyring", n, c.uid, c.gid, named, 0, Vec::new(), false)?;
                        self.keys.get_mut(&r).unwrap().ns = c.userns.clone();
                        r
                    }
                }
            }
        };
        self.holder_mut(c).session = r;
        Ok(r)
    }

    /// Whether keyring `ring` reaches `key` (or is it).
    fn reaches(&self, ring: i32, key: i32) -> bool {
        let mut seen = vec![ring];
        let mut frontier = vec![ring];
        while let Some(r) = frontier.pop() {
            if r == key {
                return true;
            }
            for l in self.keys.get(&r).map_or(&[][..], |k| &k.links[..]) {
                if !seen.contains(l) && self.keys.get(l).is_some_and(Key::is_keyring) {
                    seen.push(*l);
                    frontier.push(*l);
                }
            }
        }
        false
    }

    /// The deepest nesting of keyrings under `ring`, itself counted.
    fn depth(&self, ring: i32, seen: &mut Vec<i32>) -> usize {
        if seen.contains(&ring) {
            return 0;
        }
        seen.push(ring);
        let below = self.keys.get(&ring).map_or(0, |k| {
            k.links
                .iter()
                .filter(|l| self.keys.get(l).is_some_and(Key::is_keyring))
                .map(|l| self.depth(*l, seen))
                .max()
                .unwrap_or(0)
        });
        seen.pop();
        1 + below
    }

    /// Whether key `key` may be linked into keyring `ring` by its
    /// restriction.
    fn restriction_allows(&self, ring: i32, k: &Key) -> Result<(), i32> {
        let Some(r) = self.keys.get(&ring) else { return Err(errno::ENOKEY) };
        match &r.restrict {
            Restrict::None => Ok(()),
            Restrict::RejectAll => Err(errno::EPERM),
            Restrict::Builtin { .. } => {
                if k.kind != "asymmetric" {
                    Err(errno::EOPNOTSUPP)
                } else {
                    // The builtin keyrings hold no key to have signed it.
                    Err(errno::ENOKEY)
                }
            }
            Restrict::KeyOrKeyring(signer, chain) => {
                if k.kind != "asymmetric" {
                    return Err(errno::EOPNOTSUPP);
                }
                let trusted = self.keys.get(signer);
                let dest = chain.then_some(r);
                crate::keytypes::signed_by(self, k, trusted, dest)
            }
        }
    }

    /// Link `key` into keyring `ring`, displacing a key of the same type
    /// and description there, as Linux's `__key_link` does.
    fn link(&mut self, ring: i32, key: i32) -> Result<(), i32> {
        let r = self.keys.get(&ring).ok_or(errno::ENOKEY)?;
        if !r.is_keyring() {
            return Err(errno::ENOTDIR);
        }
        if let Some(e) = r.invalid(now()) {
            return Err(e);
        }
        if r.links.contains(&key) {
            return Ok(());
        }
        let k = self.keys[&key].clone();
        self.restriction_allows(ring, &k)?;
        if k.is_keyring() {
            if self.reaches(key, ring) {
                return Err(errno::EDEADLK);
            }
            if self.depth(key, &mut Vec::new()) + self.depth_above(ring) > MAX_DEPTH {
                return Err(errno::ELOOP);
            }
        }
        let same: Vec<i32> = self.keys[&ring]
            .links
            .iter()
            .copied()
            .filter(|l| self.keys.get(l).is_some_and(|o| o.kind == k.kind && o.desc == k.desc))
            .collect();
        // A new link costs the keyring's owner a link's bytes.
        let owner = self.keys[&ring].uid;
        if same.is_empty() && owner != NO_ID && !self.quota_ok(owner, false, LINK_BYTES) {
            return Err(errno::EDQUOT);
        }
        let r = self.keys.get_mut(&ring).unwrap();
        r.links.retain(|l| !same.contains(l));
        r.links.push(key);
        self.touched = true;
        Ok(())
    }

    /// How deep keyring `ring` is nested under the keyrings that link it,
    /// itself counted.
    fn depth_above(&self, ring: i32) -> usize {
        let mut depth = 1;
        let mut level = vec![ring];
        let mut seen = vec![ring];
        while depth <= MAX_DEPTH {
            let up: Vec<i32> = self
                .keys
                .values()
                .filter(|k| k.is_keyring() && k.links.iter().any(|l| level.contains(l)))
                .map(|k| k.serial)
                .filter(|s| !seen.contains(s))
                .collect();
            if up.is_empty() {
                break;
            }
            seen.extend(&up);
            level = up;
            depth += 1;
        }
        depth
    }

    /// Search keyring `ring` (and what it nests) for a key of `kind` and
    /// `desc`, as the caller may: the key, or the error a state of the best
    /// match gives (revoked, expired, negative), else `ENOKEY`.
    fn search_ring(&self, c: &Caller, ring: i32, kind: &str, desc: &[u8]) -> Result<i32, i32> {
        let now = now();
        let possessed = self.possessed(c);
        let mut error = errno::ENOKEY;
        let mut seen = vec![ring];
        let mut frontier = vec![(ring, 1usize)];
        while let Some((r, depth)) = frontier.pop() {
            let Some(rk) = self.keys.get(&r) else { continue };
            let pos = possessed.contains(&r);
            if Self::granted(rk, c, pos) & KEY_SEARCH == 0 || rk.invalid(now).is_some() {
                continue;
            }
            // The keyring's own keys first, then those it nests.
            for l in &rk.links {
                let Some(k) = self.keys.get(l) else { continue };
                if k.kind == kind && k.desc == desc {
                    if Self::granted(k, c, possessed.contains(l)) & KEY_SEARCH == 0 {
                        error = errno::EACCES;
                        continue;
                    }
                    if k.flags & INVALIDATED != 0 {
                        continue;
                    }
                    if let Some(e) = k.invalid(now) {
                        error = e;
                        continue;
                    }
                    if k.negative() {
                        return Err(if k.reject != 0 { k.reject } else { errno::ENOKEY });
                    }
                    return Ok(*l);
                }
            }
            if depth < MAX_DEPTH {
                for l in rk.links.iter().rev() {
                    if !seen.contains(l) && self.keys.get(l).is_some_and(Key::is_keyring) {
                        seen.push(*l);
                        frontier.push((*l, depth + 1));
                    }
                }
            }
        }
        Err(error)
    }

    /// Search the caller's keyrings (thread, process, session) as
    /// `request_key` does.
    pub(crate) fn search_process(&self, c: &Caller, kind: &str, desc: &[u8]) -> Result<i32, i32> {
        let mut error = errno::ENOKEY;
        for r in [self.thread_of(c), self.process_of(c), self.session_of(c)] {
            if r == 0 {
                continue;
            }
            match self.search_ring(c, r, kind, desc) {
                Ok(k) => return Ok(k),
                // A state error found beats not finding one.
                Err(e) if e != errno::ENOKEY && error == errno::ENOKEY => error = e,
                Err(errno::ENOKEY) => {}
                Err(e) => {
                    if error == errno::ENOKEY {
                        error = e;
                    }
                }
            }
        }
        Err(error)
    }

    /// Collect what is gone: holders of ended processes, invalidated keys,
    /// keys revoked or expired a `gc_delay` ago, and keys nothing reaches.
    fn collect(&mut self) {
        let alive = |h: &Holder| crate::procreg::alive((h.pid, h.start));
        self.holders.retain(alive);
        let now = now();
        let delay = sysctl("gc_delay");
        let dead: Vec<i32> = self
            .keys
            .values()
            .filter(|k| {
                k.flags & INVALIDATED != 0
                    || (k.flags & REVOKED != 0 && k.revoked_at + delay <= now)
                    || (k.expiry != 0 && k.expiry + delay <= now)
            })
            .map(|k| k.serial)
            .collect();
        for d in &dead {
            self.keys.remove(d);
        }
        // What the holders and users reach.
        let mut roots: Vec<i32> = Vec::new();
        for h in &self.holders {
            roots.extend(h.threads.iter().map(|(_, r)| *r));
            roots.push(h.process);
            roots.push(h.session);
        }
        for u in &self.users {
            roots.extend([u.user, u.session, u.persistent]);
        }
        let mut reached: std::collections::BTreeSet<i32> = std::collections::BTreeSet::new();
        let mut frontier: Vec<i32> = roots.into_iter().filter(|r| *r > 0).collect();
        while let Some(r) = frontier.pop() {
            if !reached.insert(r) {
                continue;
            }
            if let Some(k) = self.keys.get(&r) {
                frontier.extend(k.links.iter().copied());
                // The key a keyring's restriction trusts lives as long.
                if let Restrict::KeyOrKeyring(t, _) = k.restrict {
                    frontier.push(t);
                }
            }
        }
        self.keys.retain(|s, _| reached.contains(s));
        let keys: std::collections::BTreeSet<i32> = self.keys.keys().copied().collect();
        for k in self.keys.values_mut() {
            k.links.retain(|l| keys.contains(l));
        }
        for u in &mut self.users {
            for r in [&mut u.user, &mut u.session, &mut u.persistent] {
                if !keys.contains(r) {
                    *r = 0;
                }
            }
        }
    }
}

/// Run `f` on the store under its lock, writing it back if `f` says it
/// changed it (collecting what is gone first).
fn with<R>(f: impl FnOnce(&mut Store) -> (R, bool)) -> Result<R, i32> {
    let s = store().ok_or(errno::ENOMEM)?;
    s.update_maybe(|st| {
        let before = (st.keys.len(), st.holders.len());
        let (r, changed) = f(st);
        let mut changed = changed;
        if changed {
            st.collect();
            changed = changed || (st.keys.len(), st.holders.len()) != before;
        }
        Ok((r, changed))
    })
}

/// What a fork child inherits of this process's keyrings, noted before the
/// fork (so the child has it, copied): (this process's pid, its session
/// keyring, its request default).
pub(crate) static INHERIT: std::sync::Mutex<Option<(i32, i32, i32)>> = std::sync::Mutex::new(None);

/// Before a fork: what the child is to hold ([`INHERIT`]).
pub fn before_fork() {
    let Some(st) = existing() else { return };
    let (pid, start) = me();
    let held = st.get().holders.iter().find(|h| h.pid == pid && h.start == start).cloned();
    *INHERIT.lock().unwrap_or_else(|e| e.into_inner()) = held.map(|h| (pid, h.session, h.reqkey));
}

/// The keyrings a fork child holds: its parent's session, and the request
/// default; no thread or process keyring. Written by the parent unless the
/// child has used its keyrings first.
pub fn forked(child: i32) {
    let Some(st) = existing() else { return };
    let (pid, start) = me();
    if !st.get().holders.iter().any(|h| h.pid == pid && h.start == start) {
        return;
    }
    let Some(cstart) = crate::procreg::host_info(child).map(|i| i.0) else { return };
    let _ = with(|s| {
        let Some(h) = s.holders.iter().find(|h| h.pid == pid && h.start == start).cloned() else {
            return ((), false);
        };
        if s.holders.iter().any(|o| o.pid == child && o.start == cstart) {
            return ((), false);
        }
        s.holders.retain(|o| o.pid != child);
        s.holders.push(Holder {
            pid: child,
            start: cstart,
            session: h.session,
            reqkey: h.reqkey,
            ..Holder::default()
        });
        ((), true)
    });
}

/// An `execve`: the thread and process keyrings are let go.
pub fn exec() {
    let Some(st) = existing() else { return };
    let (pid, start) = me();
    let holds = |h: &Holder| h.pid == pid && h.start == start;
    if !st.get().holders.iter().any(|h| holds(h) && (h.process != 0 || !h.threads.is_empty())) {
        return;
    }
    let _ = with(|s| {
        let Some(h) = s.holders.iter_mut().find(|h| h.pid == pid && h.start == start) else {
            return ((), false);
        };
        let changed = h.process != 0 || !h.threads.is_empty();
        h.process = 0;
        h.threads.clear();
        ((), changed)
    });
}

/// Thread `tid` of this process ended: its thread keyring goes.
pub fn thread_exit(tid: i32) {
    // A thread holds a keyring only once its process has used the keys,
    // which opened the record: otherwise there is nothing to look at.
    let Some(st) = STORE.get().and_then(Option::as_ref) else { return };
    let (pid, start) = me();
    let holds =
        |h: &Holder| h.pid == pid && h.start == start && h.threads.iter().any(|(t, _)| *t == tid);
    if !st.get().holders.iter().any(holds) {
        return;
    }
    let _ = with(|s| {
        if let Some(h) = s.holders.iter_mut().find(|h| h.pid == pid && h.start == start) {
            h.threads.retain(|(t, _)| *t != tid);
        }
        ((), true)
    });
}

/// The type of a new key: its payload checked and prepared, its default
/// permissions, and whether it can be updated or read.
pub struct Prepared {
    pub payload: Vec<u8>,
    /// The description the type gives a key added without one.
    pub desc: Option<Vec<u8>>,
}

impl<P: Platform> Kernel<P> {
    /// The caller, as the keys see it.
    pub(crate) fn key_caller(&self) -> Caller {
        let (pid, start) = me();
        let c = &self.creds;
        let kuid = crate::userns::from_ns(c.fsuid, false).unwrap_or(crate::userns::OVERFLOW);
        let kgid = crate::userns::from_ns(c.fsgid, true).unwrap_or(crate::userns::OVERFLOW);
        Caller {
            pid,
            start,
            tid: crate::thread::tid(),
            uid: kuid,
            gid: kgid,
            groups: c.groups.iter().filter_map(|g| crate::userns::from_ns(*g, true)).collect(),
            admin: c.has(crate::caps::CAP_SYS_ADMIN),
            setuid: c.has(crate::caps::CAP_SETUID),
            userns: self.fs_opt().map_or_else(Vec::new, |f| f.ns.user_dir()),
        }
    }

    /// `add_key(type, description, payload, plen, keyring)`.
    pub(crate) fn sys_add_key(
        &mut self,
        ty: u64,
        desc: u64,
        payload: u64,
        plen: u64,
        ring: u64,
    ) -> i64 {
        if plen as usize > MAX_PAYLOAD {
            return err(errno::EINVAL);
        }
        let kind = guest!(read_type(ty));
        if kind.first() == Some(&b'.') {
            return err(errno::EPERM);
        }
        let mut desc = if desc == 0 {
            None
        } else {
            let d = guest!(uaccess::read_cstr(desc, MAX_DESC + 1));
            if d.len() > MAX_DESC {
                return err(errno::EINVAL);
            }
            (!d.is_empty()).then_some(d)
        };
        if desc.as_deref().is_some_and(|d| d.first() == Some(&b'.')) && kind == b"keyring" {
            return err(errno::EPERM);
        }
        let data = if plen > 0 {
            if payload == 0 {
                return err(errno::EFAULT);
            }
            guest!(uaccess::read_bytes(payload, plen as usize))
        } else {
            Vec::new()
        };
        let kind = String::from_utf8_lossy(&kind).into_owned();
        let c = self.key_caller();
        let r = with(|s| {
            let r = (|| {
                let (dest, _) = s.lookup(&c, ring as i32, Look::CREATE, KEY_WRITE)?;
                if !s.keys[&dest].is_keyring() {
                    return Err(errno::ENOTDIR);
                }
                let prep = crate::keytypes::preparse(s, &c, &kind, desc.as_deref(), &data)?;
                if desc.is_none() {
                    desc = prep.desc.clone();
                }
                let Some(desc) = desc.clone() else { return Err(errno::EINVAL) };
                // What the keyring's restriction allows in, first.
                let probe = Key {
                    serial: 0,
                    kind: kind.clone(),
                    desc: desc.clone(),
                    uid: c.uid,
                    gid: c.gid,
                    perm: 0,
                    flags: 0,
                    expiry: 0,
                    revoked_at: 0,
                    reject: 0,
                    payload: prep.payload.clone(),
                    links: Vec::new(),
                    restrict: Restrict::None,
                    quota: 0,
                    ns: Vec::new(),
                };
                s.restriction_allows(dest, &probe)?;
                if let Some(e) = s.keys[&dest].invalid(now()) {
                    return Err(e);
                }
                // An existing usable key of the type and description in the
                // keyring is updated, if the type allows it and the caller
                // may write it.
                if crate::keytypes::updatable(&kind)
                    && let Some(&old) = s.keys[&dest].links.iter().find(|l| {
                        s.keys.get(l).is_some_and(|k| {
                            k.kind == kind
                                && k.desc == desc
                                && k.flags & (REVOKED | INVALIDATED) == 0
                        })
                    })
                {
                    let possessed = s.possessed(&c).contains(&old);
                    if Store::granted(&s.keys[&old], &c, possessed) & KEY_WRITE == 0 {
                        return Err(errno::EACCES);
                    }
                    update_payload(s, old, prep.payload)?;
                    s.touched = true;
                    return Ok(old);
                }
                let mut perm = ((KEY_VIEW | KEY_SEARCH | KEY_LINK | KEY_SETATTR) << KEY_POS_SHIFT)
                    | (KEY_VIEW << KEY_USR_SHIFT);
                if crate::keytypes::readable(&kind) {
                    perm |= KEY_READ << KEY_POS_SHIFT;
                }
                if kind == "keyring" || crate::keytypes::updatable(&kind) {
                    perm |= KEY_WRITE << KEY_POS_SHIFT;
                }
                let key = s.alloc(&kind, &desc, c.uid, c.gid, perm, 0, prep.payload, false)?;
                s.keys.get_mut(&key).unwrap().ns = c.userns.clone();
                if let Err(e) = s.link(dest, key) {
                    s.keys.remove(&key);
                    return Err(e);
                }
                Ok(key)
            })();
            let changed = r.is_ok();
            (r, changed)
        });
        match r {
            Ok(Ok(k)) => k as i64,
            Ok(Err(e)) | Err(e) => err(e),
        }
    }

    /// `request_key(type, description, callout_info, dest_keyring)`.
    pub(crate) fn sys_request_key(&mut self, ty: u64, desc: u64, callout: u64, dest: u64) -> i64 {
        let kind = guest!(read_type(ty));
        if kind.first() == Some(&b'.') {
            return err(errno::EPERM);
        }
        let desc = guest!(uaccess::read_cstr(desc, MAX_DESC + 1));
        if desc.len() > MAX_DESC {
            return err(errno::EINVAL);
        }
        let callout = if callout == 0 {
            None
        } else {
            Some(guest!(uaccess::read_cstr(callout, MAX_DESC + 1)))
        };
        let kind = String::from_utf8_lossy(&kind).into_owned();
        let c = self.key_caller();
        let r = with(|s| {
            let r = (|| {
                // The destination: the given keyring, or the default.
                let dest = match dest as i32 {
                    0 => None,
                    d => Some(s.lookup(&c, d, Look::CREATE, KEY_WRITE)?.0),
                };
                if !crate::keytypes::known(&kind) {
                    return Err(errno::ENOKEY);
                }
                match s.search_process(&c, &kind, &desc) {
                    Ok(k) => {
                        if let Some(d) = dest {
                            let possessed = s.possessed(&c).contains(&k);
                            if Store::granted(&s.keys[&k], &c, possessed) & KEY_LINK == 0 {
                                return Err(errno::EACCES);
                            }
                            s.link(d, k)?;
                        }
                        Ok(k)
                    }
                    Err(errno::ENOKEY) if callout.is_some() => {
                        // Constructed: in the destination keyring, which the
                        // caller must be able to write.
                        let d = match dest {
                            Some(d) => d,
                            None => default_dest(s, &c)?,
                        };
                        let possessed = s.possessed(&c).contains(&d);
                        if Store::granted(&s.keys[&d], &c, possessed) & KEY_WRITE == 0 {
                            return Err(errno::EACCES);
                        }
                        let mut perm = ((KEY_VIEW | KEY_SEARCH | KEY_LINK | KEY_SETATTR)
                            << KEY_POS_SHIFT)
                            | (KEY_VIEW << KEY_USR_SHIFT);
                        if crate::keytypes::readable(&kind) {
                            perm |= KEY_READ << KEY_POS_SHIFT;
                        }
                        if kind == "keyring" || crate::keytypes::updatable(&kind) {
                            perm |= KEY_WRITE << KEY_POS_SHIFT;
                        }
                        let key =
                            s.alloc(&kind, &desc, c.uid, c.gid, perm, 0, Vec::new(), false)?;
                        // No helper instantiates it: negated, as a failed
                        // construction leaves it.
                        let k = s.keys.get_mut(&key).unwrap();
                        k.flags |= NEGATIVE;
                        k.reject = errno::ENOKEY;
                        k.expiry = now() + NEGATIVE_TIMEOUT;
                        if let Err(e) = s.link(d, key) {
                            s.keys.remove(&key);
                            return Err(e);
                        }
                        Err(errno::ENOKEY)
                    }
                    Err(e) => Err(e),
                }
            })();
            let changed = s.touched;
            (r, changed)
        });
        match r {
            Ok(Ok(k)) => k as i64,
            Ok(Err(e)) | Err(e) => err(e),
        }
    }

    /// `keyctl(operation, ...)`.
    pub(crate) fn sys_keyctl(&mut self, op: u64, a: [u64; 4]) -> i64 {
        let c = self.key_caller();
        let id = a[0] as i32;
        match op {
            KEYCTL_GET_KEYRING_ID => {
                let look = if a[1] != 0 { Look::CREATE } else { Look::PLAIN };
                result(with(|s| {
                    let r = s.lookup(&c, id, look, 0).map(|(k, _)| k as i64);
                    (r, s.touched)
                }))
            }
            KEYCTL_JOIN_SESSION_KEYRING => {
                let name = if a[0] == 0 {
                    None
                } else {
                    let n = guest!(uaccess::read_cstr(a[0], MAX_DESC + 1));
                    if n.len() > MAX_DESC {
                        return err(errno::EINVAL);
                    }
                    Some(n)
                };
                result(with(|s| (s.join(&c, name.as_deref()).map(i64::from), true)))
            }
            KEYCTL_UPDATE => {
                if a[2] as usize > PAGE {
                    return err(errno::EINVAL);
                }
                let data = if a[2] > 0 {
                    if a[1] == 0 {
                        return err(errno::EFAULT);
                    }
                    guest!(uaccess::read_bytes(a[1], a[2] as usize))
                } else {
                    Vec::new()
                };
                result(with(|s| {
                    let r = (|| {
                        let (k, _) = s.lookup(&c, id, Look::PLAIN, KEY_WRITE)?;
                        let kind = s.keys[&k].kind.clone();
                        if !crate::keytypes::updatable(&kind) {
                            return Err(errno::EOPNOTSUPP);
                        }
                        if let Some(e) = s.keys[&k].invalid(now()) {
                            return Err(e);
                        }
                        let desc = s.keys[&k].desc.clone();
                        let prep = crate::keytypes::preparse_update(s, &c, k, &kind, &desc, &data)?;
                        update_payload(s, k, prep)?;
                        Ok(0)
                    })();
                    let changed = r.is_ok();
                    (r, changed)
                }))
            }
            KEYCTL_REVOKE => result(with(|s| {
                let r = (|| {
                    let k = match s.lookup(&c, id, Look::PLAIN, KEY_WRITE) {
                        Err(errno::EACCES) => s.lookup(&c, id, Look::PLAIN, KEY_SETATTR)?.0,
                        r => r?.0,
                    };
                    let key = s.keys.get_mut(&k).unwrap();
                    if key.flags & REVOKED == 0 {
                        key.flags |= REVOKED;
                        key.revoked_at = now();
                    }
                    Ok(0)
                })();
                (r, true)
            })),
            KEYCTL_CHOWN => self.key_chown(&c, id, a[1] as i32, a[2] as i32),
            KEYCTL_SETPERM => {
                let perm = a[1] as u32;
                let all = (KEY_ALL << KEY_POS_SHIFT)
                    | (KEY_ALL << KEY_USR_SHIFT)
                    | (KEY_ALL << KEY_GRP_SHIFT)
                    | KEY_ALL;
                if perm & !all != 0 {
                    return err(errno::EINVAL);
                }
                result(with(|s| {
                    let r = (|| {
                        let (k, _) = s.lookup(&c, id, Look::CREATE_PARTIAL, KEY_SETATTR)?;
                        let key = s.keys.get_mut(&k).unwrap();
                        if key.uid != c.uid && !c.admin {
                            return Err(errno::EACCES);
                        }
                        key.perm = perm;
                        Ok(0)
                    })();
                    (r, true)
                }))
            }
            KEYCTL_DESCRIBE => {
                let r = with(|s| {
                    let r = s.lookup(&c, id, Look::PARTIAL, KEY_VIEW).map(|(k, _)| {
                        let k = &s.keys[&k];
                        let uid = to_ns_id(k.uid, false);
                        let gid = to_ns_id(k.gid, true);
                        let mut d = format!("{};{uid};{gid};{:08x};", k.kind, k.perm).into_bytes();
                        d.extend_from_slice(&k.desc);
                        d.push(0);
                        d
                    });
                    (r, s.touched)
                });
                self.copy_out(r, a[1], a[2], false)
            }
            KEYCTL_CLEAR => result(with(|s| {
                let r = (|| {
                    let k = match s.lookup(&c, id, Look::CREATE, KEY_WRITE) {
                        Err(errno::EACCES) if c.admin => {
                            let (k, _) = s.lookup(&c, id, Look::CREATE, 0)?;
                            if s.keys[&k].flags & ROOT_CAN_CLEAR == 0 {
                                return Err(errno::EACCES);
                            }
                            k
                        }
                        r => r?.0,
                    };
                    let key = s.keys.get_mut(&k).unwrap();
                    if !key.is_keyring() {
                        return Err(errno::ENOTDIR);
                    }
                    key.links.clear();
                    Ok(0)
                })();
                (r, true)
            })),
            KEYCTL_LINK => result(with(|s| {
                let r = (|| {
                    let (ring, _) = s.lookup(&c, a[1] as i32, Look::CREATE, KEY_WRITE)?;
                    let (k, _) = s.lookup(&c, id, Look::CREATE, KEY_LINK)?;
                    if let Some(e) = s.keys[&k].invalid(now()) {
                        return Err(e);
                    }
                    s.link(ring, k)?;
                    Ok(0)
                })();
                (r, true)
            })),
            KEYCTL_UNLINK => result(with(|s| {
                let r = (|| {
                    let (ring, _) = s.lookup(&c, a[1] as i32, Look::PLAIN, KEY_WRITE)?;
                    // The key is only named: no permission on it is needed.
                    let (k, _) = s.lookup(&c, id, Look::PLAIN, 0)?;
                    let r = s.keys.get_mut(&ring).unwrap();
                    if !r.is_keyring() {
                        return Err(errno::ENOTDIR);
                    }
                    let before = r.links.len();
                    r.links.retain(|l| *l != k);
                    if r.links.len() == before {
                        return Err(errno::ENOENT);
                    }
                    Ok(0)
                })();
                (r, true)
            })),
            KEYCTL_SEARCH => {
                let kind = guest!(read_type(a[1]));
                let desc = guest!(uaccess::read_cstr(a[2], MAX_DESC + 1));
                let kind = String::from_utf8_lossy(&kind).into_owned();
                result(with(|s| {
                    let r = (|| {
                        let (ring, _) = s.lookup(&c, id, Look::PLAIN, KEY_SEARCH)?;
                        let dest = match a[3] as i32 {
                            0 => None,
                            d => Some(s.lookup(&c, d, Look::CREATE, KEY_WRITE)?.0),
                        };
                        if !s.keys[&ring].is_keyring() {
                            return Err(errno::ENOTDIR);
                        }
                        let k = s.search_ring(&c, ring, &kind, &desc)?;
                        if let Some(d) = dest {
                            let possessed = s.possessed(&c).contains(&k);
                            if Store::granted(&s.keys[&k], &c, possessed) & KEY_LINK == 0 {
                                return Err(errno::EACCES);
                            }
                            s.link(d, k)?;
                        }
                        Ok(k as i64)
                    })();
                    (r, s.touched)
                }))
            }
            KEYCTL_READ => {
                let r = with(|s| {
                    let r = (|| -> Result<(Vec<u8>, bool), i32> {
                        // Any failure to find it is ENOKEY, as Linux has it.
                        let (k, possessed) =
                            s.lookup(&c, id, Look::PLAIN, 0).map_err(|_| errno::ENOKEY)?;
                        let key = &s.keys[&k];
                        if key.negative() {
                            return Err(if key.reject != 0 { key.reject } else { errno::ENOKEY });
                        }
                        if Store::granted(key, &c, possessed) & KEY_READ == 0 && !possessed {
                            return Err(errno::EACCES);
                        }
                        if !crate::keytypes::readable(&key.kind) {
                            return Err(errno::EOPNOTSUPP);
                        }
                        if let Some(e) = key.invalid(now()) {
                            return Err(e);
                        }
                        if key.is_keyring() {
                            let list = key.links.iter().flat_map(|l| l.to_ne_bytes()).collect();
                            return Ok((list, true));
                        }
                        crate::keytypes::read(s, &c, k, a[2] as usize).map(|d| (d, false))
                    })();
                    (r, s.touched)
                });
                self.copy_out(r.map(|r| r.map(|(d, _)| d)), a[1], a[2], false)
            }
            KEYCTL_INSTANTIATE | KEYCTL_INSTANTIATE_IOV | KEYCTL_NEGATE => err(errno::EPERM),
            KEYCTL_REJECT => {
                let e = a[2] as i64;
                if e <= 0 || e >= 4096 || matches!(e, 512..=516) {
                    return err(errno::EINVAL);
                }
                err(errno::EPERM)
            }
            KEYCTL_SET_REQKEY_KEYRING => result(with(|s| {
                let r = (|| {
                    let old = s.holder(&c).map_or(0, |h| h.reqkey);
                    match id {
                        KEY_REQKEY_DEFL_NO_CHANGE => return Ok(old as i64),
                        KEY_REQKEY_DEFL_THREAD_KEYRING => {
                            s.lookup(&c, KEY_SPEC_THREAD_KEYRING, Look::CREATE, 0)?;
                        }
                        KEY_REQKEY_DEFL_PROCESS_KEYRING => {
                            s.lookup(&c, KEY_SPEC_PROCESS_KEYRING, Look::CREATE, 0)?;
                        }
                        KEY_REQKEY_DEFL_DEFAULT
                        | KEY_REQKEY_DEFL_SESSION_KEYRING
                        | KEY_REQKEY_DEFL_USER_KEYRING
                        | KEY_REQKEY_DEFL_USER_SESSION_KEYRING
                        | KEY_REQKEY_DEFL_REQUESTOR_KEYRING => {}
                        _ => return Err(errno::EINVAL),
                    }
                    s.holder_mut(&c).reqkey = id;
                    Ok(old as i64)
                })();
                (r, true)
            })),
            KEYCTL_SET_TIMEOUT => result(with(|s| {
                let r = (|| {
                    let (k, _) = s.lookup(&c, id, Look::CREATE_PARTIAL, KEY_SETATTR)?;
                    let key = s.keys.get_mut(&k).unwrap();
                    key.expiry = if a[1] == 0 { 0 } else { now() + a[1] as u32 as u64 };
                    Ok(0)
                })();
                (r, true)
            })),
            KEYCTL_ASSUME_AUTHORITY => match id {
                0 => 0,
                i if i < 0 && i != KEY_SPEC_REQKEY_AUTH_KEY => err(errno::EINVAL),
                _ => err(errno::ENOKEY),
            },
            KEYCTL_GET_SECURITY => {
                let r = with(|s| {
                    let r = match s.lookup(&c, id, Look::PARTIAL, KEY_VIEW) {
                        // Viewing a key under construction needs its
                        // authorisation key, which there is none of.
                        Err(errno::EACCES) => Err(errno::ENOKEY),
                        // No security module labels it: an empty label.
                        r => r.map(|_| vec![0u8]),
                    };
                    (r, s.touched)
                });
                self.copy_out(r, a[1], a[2], true)
            }
            KEYCTL_SESSION_TO_PARENT => self.session_to_parent(&c),
            KEYCTL_INVALIDATE => result(with(|s| {
                let r = (|| {
                    let k = match s.lookup(&c, id, Look::PLAIN, KEY_SEARCH) {
                        Err(errno::EACCES) if c.admin => {
                            let (k, _) = s.lookup(&c, id, Look::PLAIN, 0)?;
                            if s.keys[&k].flags & ROOT_CAN_CLEAR == 0 {
                                return Err(errno::EACCES);
                            }
                            k
                        }
                        r => r?.0,
                    };
                    s.keys.get_mut(&k).unwrap().flags |= INVALIDATED;
                    Ok(0)
                })();
                (r, true)
            })),
            KEYCTL_GET_PERSISTENT => self.key_persistent(&c, a[0] as i32, a[1] as i32),
            KEYCTL_DH_COMPUTE => self.dh_compute(&c, a[0], a[1], a[2], a[3]),
            KEYCTL_PKEY_QUERY => self.pkey_query(&c, a),
            KEYCTL_PKEY_ENCRYPT | KEYCTL_PKEY_DECRYPT | KEYCTL_PKEY_SIGN | KEYCTL_PKEY_VERIFY => {
                self.pkey_op(&c, op, a)
            }
            KEYCTL_RESTRICT_KEYRING => self.restrict_keyring(&c, id, a[1], a[2]),
            KEYCTL_MOVE => {
                if a[3] & !KEYCTL_MOVE_EXCL != 0 {
                    return err(errno::EINVAL);
                }
                result(with(|s| {
                    let r = (|| {
                        let (k, _) = s.lookup(&c, id, Look::PLAIN, KEY_LINK)?;
                        let (from, _) = s.lookup(&c, a[1] as i32, Look::PLAIN, KEY_WRITE)?;
                        let (to, _) = s.lookup(&c, a[2] as i32, Look::CREATE, KEY_WRITE)?;
                        if !s.keys[&from].is_keyring() || !s.keys[&to].is_keyring() {
                            return Err(errno::ENOTDIR);
                        }
                        if from == to {
                            return Ok(0);
                        }
                        if !s.keys[&from].links.contains(&k) {
                            return Err(errno::ENOENT);
                        }
                        let key = &s.keys[&k];
                        if a[3] & KEYCTL_MOVE_EXCL != 0 {
                            let (kind, desc) = (key.kind.clone(), key.desc.clone());
                            if s.keys[&to].links.iter().any(|l| {
                                s.keys.get(l).is_some_and(|o| o.kind == kind && o.desc == desc)
                            }) {
                                return Err(errno::EEXIST);
                            }
                        }
                        if s.keys[&k].is_keyring() && s.reaches(k, to) {
                            return Err(errno::EDEADLK);
                        }
                        s.link(to, k)?;
                        s.keys.get_mut(&from).unwrap().links.retain(|l| *l != k);
                        Ok(0)
                    })();
                    (r, true)
                }))
            }
            KEYCTL_CAPABILITIES => {
                let caps = [
                    KEYCTL_CAPS0_CAPABILITIES
                        | KEYCTL_CAPS0_PERSISTENT_KEYRINGS
                        | KEYCTL_CAPS0_DIFFIE_HELLMAN
                        | KEYCTL_CAPS0_PUBLIC_KEY
                        | KEYCTL_CAPS0_BIG_KEY
                        | KEYCTL_CAPS0_INVALIDATE
                        | KEYCTL_CAPS0_RESTRICT_KEYRING
                        | KEYCTL_CAPS0_MOVE,
                    KEYCTL_CAPS1_NS_KEYRING_NAME | KEYCTL_CAPS1_NS_KEY_TAG,
                ];
                let n = (a[1] as usize).min(caps.len());
                if n > 0 {
                    guest!(uaccess::write_from(a[0], &caps[..n]));
                }
                caps.len() as i64
            }
            // Key notifications need a watch queue, which is not built.
            KEYCTL_WATCH_KEY => err(errno::EOPNOTSUPP),
            _ => err(errno::EOPNOTSUPP),
        }
    }

    /// Copy `r`'s bytes out to `buf` (`len` bytes long), returning their
    /// full length: all of them if they fit, else nothing (or with
    /// `partial`, what fits).
    fn copy_out(
        &self,
        r: Result<Result<Vec<u8>, i32>, i32>,
        buf: u64,
        len: u64,
        partial: bool,
    ) -> i64 {
        let data = match r {
            Ok(Ok(d)) => d,
            Ok(Err(e)) | Err(e) => return err(e),
        };
        if buf != 0 && len > 0 && (partial || len as usize >= data.len()) {
            let n = (len as usize).min(data.len());
            guest!(uaccess::write_from(buf, &data[..n]));
        }
        data.len() as i64
    }

    /// `KEYCTL_CHOWN`: a new owner needs `CAP_SYS_ADMIN`; a new group, that
    /// or owning the key and being in the group. Ids of -1 stay.
    fn key_chown(&self, c: &Caller, id: i32, uid: i32, gid: i32) -> i64 {
        let kuid = if uid == -1 { None } else { crate::userns::from_ns(uid as u32, false) };
        let kgid = if gid == -1 { None } else { crate::userns::from_ns(gid as u32, true) };
        if (uid != -1 && kuid.is_none()) || (gid != -1 && kgid.is_none()) {
            return err(errno::EINVAL);
        }
        result(with(|s| {
            let r = (|| {
                let (k, _) = s.lookup(c, id, Look::CREATE_PARTIAL, KEY_SETATTR)?;
                let key = s.keys[&k].clone();
                if let Some(u) = kuid
                    && u != key.uid
                {
                    if !c.admin {
                        return Err(errno::EACCES);
                    }
                    if !s.quota_ok(u, true, key.quota as u64) {
                        return Err(errno::EDQUOT);
                    }
                }
                if let Some(g) = kgid
                    && g != key.gid
                    && !c.admin
                    && g != c.gid
                    && !c.groups.contains(&g)
                {
                    return Err(errno::EACCES);
                }
                let key = s.keys.get_mut(&k).unwrap();
                if let Some(u) = kuid {
                    key.uid = u;
                }
                if let Some(g) = kgid {
                    key.gid = g;
                }
                Ok(0)
            })();
            (r, true)
        }))
    }

    /// `KEYCTL_GET_PERSISTENT`: user `uid`'s persistent keyring (-1: the
    /// caller's), made if missing, linked into `dest`. Another user's needs
    /// `CAP_SETUID`.
    fn key_persistent(&self, c: &Caller, uid: i32, dest: i32) -> i64 {
        let kuid = if uid == -1 {
            c.uid
        } else {
            match crate::userns::from_ns(uid as u32, false) {
                Some(u) => u,
                None => return err(errno::EINVAL),
            }
        };
        if kuid != c.uid && !c.setuid {
            return err(errno::EPERM);
        }
        result(with(|s| {
            let r = (|| {
                let (d, _) = s.lookup(c, dest, Look::CREATE, KEY_WRITE)?;
                s.user_rings(kuid);
                let i = s.users.iter().position(|u| u.uid == kuid).unwrap();
                let mut p = s.users[i].persistent;
                if p == 0 || !s.live(p) {
                    let perm = ((KEY_ALL & !KEY_SETATTR) << KEY_POS_SHIFT)
                        | ((KEY_VIEW | KEY_READ) << KEY_USR_SHIFT);
                    let desc = format!("_persistent.{kuid}");
                    p = s.alloc(
                        "keyring",
                        desc.as_bytes(),
                        kuid,
                        NO_ID,
                        perm,
                        ROOT_CAN_CLEAR,
                        Vec::new(),
                        true,
                    )?;
                    s.users[i].persistent = p;
                }
                // Kept a while after each use.
                s.keys.get_mut(&p).unwrap().expiry = now() + sysctl("persistent_keyring_expiry");
                s.link(d, p)?;
                Ok(p as i64)
            })();
            (r, true)
        }))
    }

    /// `KEYCTL_SESSION_TO_PARENT`: the caller's session keyring becomes its
    /// parent's, as Linux allows it: the parent an fwe process whose user
    /// and group ids (real, effective, saved) are all the caller's
    /// effective ones, and both session keyrings that user's.
    fn session_to_parent(&self, c: &Caller) -> i64 {
        // SAFETY: getppid cannot fail.
        let ppid = unsafe { libc::getppid() };
        let Some(pstart) = crate::procreg::host_info(ppid).map(|i| i.0) else {
            return err(errno::EPERM);
        };
        let Some(rec) = crate::procreg::read(ppid) else { return err(errno::EPERM) };
        let euid =
            crate::userns::from_ns(self.creds.euid, false).unwrap_or(crate::userns::OVERFLOW);
        let egid = crate::userns::from_ns(self.creds.egid, true).unwrap_or(crate::userns::OVERFLOW);
        let ids = rec.ids;
        if ids[0..3].iter().any(|&u| u != euid) || ids[4..7].iter().any(|&g| g != egid) {
            return err(errno::EPERM);
        }
        result(with(|s| {
            let r = (|| {
                let (ses, _) = s.lookup(c, KEY_SPEC_SESSION_KEYRING, Look::PLAIN, KEY_LINK)?;
                let parent = Caller { pid: ppid, start: pstart, ..c.clone() };
                let theirs = s.holder(&parent).map_or(0, |h| h.session);
                let owner = |k: i32| s.keys.get(&k).map(|k| k.uid);
                if owner(ses) != Some(euid)
                    || (theirs != 0 && owner(theirs).is_some_and(|u| u != euid))
                {
                    return Err(errno::EPERM);
                }
                s.holder_mut(&parent).session = ses;
                Ok(0)
            })();
            (r, true)
        }))
    }

    /// `KEYCTL_DH_COMPUTE(params, buffer, buflen, kdf)`: the shared secret
    /// of the private, prime and base numbers three `user` keys hold (or,
    /// with KDF parameters, `buflen` bytes derived from it), in Linux's
    /// order of checks.
    fn dh_compute(&self, c: &Caller, params: u64, buf: u64, len: u64, kdf: u64) -> i64 {
        use crate::keycrypto as kc;
        if params == 0 || (buf == 0 && len != 0) {
            return err(errno::EINVAL);
        }
        let ids: [i32; 3] = guest!(uaccess::read(params));
        let kdf = if kdf == 0 {
            None
        } else {
            let raw = guest!(uaccess::read_bytes(kdf, 52));
            let word = |at: usize| u64::from_ne_bytes(raw[at..at + 8].try_into().unwrap());
            let oi_len = u32::from_ne_bytes(raw[16..20].try_into().unwrap()) as usize;
            if raw[20..52].iter().any(|&b| b != 0) {
                return err(errno::EINVAL);
            }
            if len as usize > kc::KDF_MAX_OUTPUT_LEN || oi_len > kc::KDF_MAX_OI_LEN {
                return err(errno::EMSGSIZE);
            }
            let hash = guest!(uaccess::read_cstr(word(0), 128));
            let hash = String::from_utf8_lossy(&hash).into_owned();
            if kc::hash_size(&hash).is_none() {
                return err(errno::ENOENT);
            }
            let other =
                if oi_len > 0 { guest!(uaccess::read_bytes(word(8), oi_len)) } else { Vec::new() };
            Some((hash, other))
        };
        let numbers = with(|s| {
            let r = (|| {
                let mut out = Vec::new();
                // The prime, the private key, then the base, as Linux reads
                // them.
                for id in [ids[1], ids[0], ids[2]] {
                    let (k, _) = s.lookup(c, id, Look::PLAIN, KEY_READ)?;
                    let key = &s.keys[&k];
                    if key.kind != "user" {
                        return Err(errno::EOPNOTSUPP);
                    }
                    if let Some(e) = key.invalid(now()) {
                        return Err(e);
                    }
                    out.push(key.payload.clone());
                }
                Ok(out)
            })();
            (r, false)
        });
        let n = match numbers {
            Ok(Ok(n)) => n,
            Ok(Err(e)) | Err(e) => return err(e),
        };
        let (prime, private, base) = (&n[0], &n[1], &n[2]);
        let size = match kc::dh_secret_len(base, private, prime) {
            Ok(s) => s,
            Err(e) => return err(e),
        };
        let out = match &kdf {
            None => {
                if len == 0 {
                    return size as i64;
                }
                if (len as usize) < size {
                    return err(errno::EOVERFLOW);
                }
                match kc::dh_compute(base, private, prime) {
                    Ok(o) => o,
                    Err(e) => return err(e),
                }
            }
            Some((hash, other)) => {
                let secret = match kc::dh_compute(base, private, prime) {
                    Ok(o) => o,
                    Err(e) => return err(e),
                };
                match kc::dh_kdf(hash, &secret, other, len as usize) {
                    Some(o) => o,
                    None => return err(errno::ENOENT),
                }
            }
        };
        if !out.is_empty() {
            guest!(uaccess::write_from(buf, &out));
        }
        out.len() as i64
    }

    /// The asymmetric key `id` names, for a public-key operation: the info
    /// string read, the key searchable by the caller and asymmetric.
    fn pkey_key(
        &self,
        c: &Caller,
        id: i32,
        info: u64,
    ) -> Result<(crate::keycrypto::Asym, String), i32> {
        let info = uaccess::read_cstr(info, 4096)?;
        let info = String::from_utf8_lossy(&info).into_owned();
        let r = with(|s| {
            let r = (|| {
                let (k, _) = s.lookup(c, id, Look::PLAIN, KEY_SEARCH)?;
                let key = &s.keys[&k];
                if let Some(e) = key.invalid(now()) {
                    return Err(e);
                }
                if key.kind != "asymmetric" {
                    return Err(errno::EOPNOTSUPP);
                }
                crate::keytypes::crypto::asym(key)
            })();
            (r, false)
        });
        match r {
            Ok(Ok(a)) => Ok((a, info)),
            Ok(Err(e)) | Err(e) => Err(e),
        }
    }

    /// `KEYCTL_PKEY_QUERY(key, reserved, info, query)`: what the key can do
    /// and its sizes, as `struct keyctl_pkey_query`.
    fn pkey_query(&self, c: &Caller, a: [u64; 4]) -> i64 {
        if a[1] != 0 {
            return err(errno::EINVAL);
        }
        let (key, info) = match self.pkey_key(c, a[0] as i32, a[2]) {
            Ok(k) => k,
            Err(e) => return err(e),
        };
        let q = match crate::keycrypto::pkey_query(&key, &info) {
            Ok(q) => q,
            Err(e) => return err(e),
        };
        let mut out = [0u8; 56];
        out[0..4].copy_from_slice(&q.supported_ops.to_ne_bytes());
        out[4..8].copy_from_slice(&q.key_size.to_ne_bytes());
        out[8..10].copy_from_slice(&q.max_data_size.to_ne_bytes());
        out[10..12].copy_from_slice(&q.max_sig_size.to_ne_bytes());
        out[12..14].copy_from_slice(&q.max_enc_size.to_ne_bytes());
        out[14..16].copy_from_slice(&q.max_dec_size.to_ne_bytes());
        guest!(uaccess::write_from(a[3], &out));
        0
    }

    /// `KEYCTL_PKEY_ENCRYPT`, `DECRYPT`, `SIGN` (`params, info, in, out`)
    /// and `VERIFY` (`params, info, data, signature`), with
    /// `struct keyctl_pkey_params` giving the key and the lengths.
    fn pkey_op(&self, c: &Caller, op: u64, a: [u64; 4]) -> i64 {
        use crate::keycrypto as kc;
        let raw = guest!(uaccess::read_bytes(a[0], 40));
        let word = |at: usize| u32::from_ne_bytes(raw[at..at + 4].try_into().unwrap());
        if raw[12..40].iter().any(|&b| b != 0) {
            return err(errno::EINVAL);
        }
        let (id, in_len, out_len) = (word(0) as i32, word(4) as usize, word(8) as usize);
        let (key, info) = match self.pkey_key(c, id, a[1]) {
            Ok(k) => k,
            Err(e) => return err(e),
        };
        let input = guest!(uaccess::read_bytes(a[2], in_len));
        if op == KEYCTL_PKEY_VERIFY {
            let sig = guest!(uaccess::read_bytes(a[3], out_len));
            return match kc::pkey_verify(&key, &info, &input, &sig) {
                Ok(()) => 0,
                Err(e) => err(e),
            };
        }
        let r = match op {
            KEYCTL_PKEY_ENCRYPT => {
                kc::pkey_encrypt(&key, &info, &input, out_len, &mut crate::host::fill_random)
            }
            KEYCTL_PKEY_DECRYPT => kc::pkey_decrypt(&key, &info, &input, out_len),
            _ => kc::pkey_sign(&key, &info, &input, out_len),
        };
        match r {
            Ok(out) => {
                guest!(uaccess::write_from(a[3], &out));
                out.len() as i64
            }
            Err(e) => err(e),
        }
    }

    /// `KEYCTL_RESTRICT_KEYRING(keyring, type, restriction)`.
    fn restrict_keyring(&self, c: &Caller, id: i32, ty: u64, restriction: u64) -> i64 {
        let ty = if ty == 0 { None } else { Some(guest!(read_type(ty))) };
        let restriction = if restriction == 0 {
            None
        } else {
            Some(guest!(uaccess::read_cstr(restriction, MAX_DESC + 1)))
        };
        result(with(|s| {
            let r = (|| {
                let (ring, _) = s.lookup(c, id, Look::PLAIN, KEY_SETATTR)?;
                let parsed = match (&ty, &restriction) {
                    (None, None) => Restrict::RejectAll,
                    (None, Some(_)) | (Some(_), None) => return Err(errno::EINVAL),
                    (Some(t), Some(r)) => {
                        if !s.keys[&ring].is_keyring() {
                            return Err(errno::ENOTDIR);
                        }
                        let t = String::from_utf8_lossy(t);
                        if !crate::keytypes::known(&t) {
                            return Err(errno::ENOKEY);
                        }
                        if t != "asymmetric" {
                            return Err(errno::ENOENT);
                        }
                        parse_restriction(s, r)?
                    }
                };
                let key = &s.keys[&ring];
                if !key.is_keyring() {
                    return Err(errno::ENOTDIR);
                }
                if key.restrict != Restrict::None {
                    return Err(errno::EEXIST);
                }
                if let Restrict::KeyOrKeyring(target, _) = parsed
                    && (target == ring || s.restriction_reaches(target, ring))
                {
                    return Err(errno::EDEADLK);
                }
                s.keys.get_mut(&ring).unwrap().restrict = parsed;
                Ok(0)
            })();
            (r, true)
        }))
    }
}

impl Store {
    /// Whether keyring `from`'s restriction chain leads to `ring`.
    fn restriction_reaches(&self, from: i32, ring: i32) -> bool {
        let mut at = from;
        let mut seen = Vec::new();
        while let Some(Restrict::KeyOrKeyring(next, _)) = self.keys.get(&at).map(|k| &k.restrict) {
            if *next == ring {
                return true;
            }
            if seen.contains(next) {
                return false;
            }
            seen.push(*next);
            at = *next;
        }
        false
    }
}

/// An asymmetric restriction: `builtin_trusted`,
/// `builtin_and_secondary_trusted`, or `key_or_keyring:<serial>[:chain]`.
fn parse_restriction(s: &Store, r: &[u8]) -> Result<Restrict, i32> {
    match r {
        b"builtin_trusted" => Ok(Restrict::Builtin { secondary: false }),
        b"builtin_and_secondary_trusted" => Ok(Restrict::Builtin { secondary: true }),
        _ => {
            let rest = r.strip_prefix(b"key_or_keyring:").ok_or(errno::EINVAL)?;
            let text = std::str::from_utf8(rest).map_err(|_| errno::EINVAL)?;
            let (num, chain) = match text.split_once(':') {
                Some((n, "chain")) => (n, true),
                Some(_) => return Err(errno::EINVAL),
                None => (text, false),
            };
            let serial = parse_serial(num).ok_or(errno::EINVAL)?;
            if serial == 0 {
                return Err(errno::EINVAL);
            }
            let key = s.keys.get(&serial).ok_or(errno::ENOKEY)?;
            if !key.is_keyring() && key.kind != "asymmetric" {
                return Err(errno::EOPNOTSUPP);
            }
            Ok(Restrict::KeyOrKeyring(serial, chain))
        }
    }
}

/// A serial as the kernel's `kstrtos32` takes it: decimal, or hex or octal
/// by prefix.
fn parse_serial(t: &str) -> Option<i32> {
    let (digits, radix) = if let Some(h) = t.strip_prefix("0x") {
        (h, 16)
    } else if t.len() > 1 && t.starts_with('0') {
        (&t[1..], 8)
    } else {
        (t, 10)
    };
    i32::from_str_radix(digits, radix).ok()
}

/// Replace key `k`'s payload with `payload`, its owner's quota allowing.
fn update_payload(s: &mut Store, k: i32, payload: Vec<u8>) -> Result<(), i32> {
    let key = &s.keys[&k];
    let quota = (key.desc.len() + 1 + crate::keytypes::charge(&key.kind, &payload)) as u32;
    if quota > key.quota && !s.quota_ok(key.uid, false, (quota - key.quota) as u64) {
        return Err(errno::EDQUOT);
    }
    let key = s.keys.get_mut(&k).unwrap();
    key.payload = payload;
    key.quota = quota;
    // A negative key so instantiated loses its negative timeout.
    if key.flags & NEGATIVE != 0 {
        key.flags &= !NEGATIVE;
        key.reject = 0;
        key.expiry = 0;
    }
    Ok(())
}

/// The keyring a constructed key goes into by the caller's
/// `KEYCTL_SET_REQKEY_KEYRING` choice.
fn default_dest(s: &mut Store, c: &Caller) -> Result<i32, i32> {
    let choice = s.holder(c).map_or(0, |h| h.reqkey);
    if choice == KEY_REQKEY_DEFL_USER_KEYRING {
        return Ok(s.user_rings(c.uid).user);
    }
    // From the chosen keyring on, the first the caller has: thread,
    // process, session, then its user's session keyring. None is made.
    let start = match choice {
        KEY_REQKEY_DEFL_PROCESS_KEYRING => 1,
        KEY_REQKEY_DEFL_SESSION_KEYRING => 2,
        KEY_REQKEY_DEFL_USER_SESSION_KEYRING => 3,
        _ => 0,
    };
    let own = [s.thread_of(c), s.process_of(c), s.holder(c).map_or(0, |h| h.session)];
    if let Some(&r) = own.iter().skip(start).find(|&&r| r != 0 && s.live(r)) {
        return Ok(r);
    }
    Ok(s.user_rings(c.uid).session)
}

/// A key type's name, as `add_key`, `request_key` and `keyctl` copy it: at
/// most 31 bytes (`EINVAL` beyond), and not empty.
fn read_type(addr: u64) -> Result<Vec<u8>, i32> {
    let t = uaccess::read_cstr(addr, 33)?;
    if t.is_empty() || t.len() > 31 {
        return Err(errno::EINVAL);
    }
    Ok(t)
}

/// An id of the initial user namespace as the caller's namespace shows it.
fn to_ns_id(id: u32, gid: bool) -> u32 {
    if id == NO_ID { crate::userns::OVERFLOW } else { crate::userns::to_ns(id, gid) }
}

/// A store result as a system call's.
fn result(r: Result<Result<i64, i32>, i32>) -> i64 {
    match r {
        Ok(Ok(v)) => v,
        Ok(Err(e)) | Err(e) => err(e),
    }
}

/// `/proc/keys`: the keys the reader may view.
pub fn proc_keys(c: &Caller) -> Vec<u8> {
    let Some(st) = existing() else { return Vec::new() };
    let s = st.get();
    let possessed = s.possessed(c);
    let now = now();
    let mut out = Vec::new();
    for k in s.keys.values() {
        let pos = possessed.contains(&k.serial);
        if Store::granted(k, c, pos) & KEY_VIEW == 0 {
            continue;
        }
        let timeout = if k.expiry == 0 {
            "perm".to_string()
        } else if k.expiry <= now {
            "expd".to_string()
        } else {
            let left = k.expiry - now;
            match left {
                0..60 => format!("{left}s"),
                60..3600 => format!("{}m", left / 60),
                3600..86400 => format!("{}h", left / 3600),
                86400..604800 => format!("{}d", left / 86400),
                _ => format!("{}w", left / 604800),
            }
        };
        let flag = |b: bool, ch: char| if b { ch } else { '-' };
        let line = format!(
            "{:08x} {}{}{}{}{}{}{} {:5} {:>4} {:08x} {:5} {:5} {:<9.9} ",
            k.serial,
            'I',
            flag(k.flags & REVOKED != 0, 'R'),
            flag(k.flags & (INVALIDATED | REVOKED) != 0 && k.revoked_at != 0, 'D'),
            flag(k.flags & IN_QUOTA != 0, 'Q'),
            '-',
            flag(k.negative(), 'N'),
            flag(k.flags & INVALIDATED != 0, 'i'),
            1,
            timeout,
            k.perm,
            to_ns_id(k.uid, false),
            to_ns_id(k.gid, true),
            k.kind,
        );
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(&crate::keytypes::describe(&s, k));
        out.push(b'\n');
    }
    out
}

/// `/proc/key-users`: each user's keys and quota.
pub fn proc_key_users() -> Vec<u8> {
    let Some(st) = existing() else { return Vec::new() };
    let s = st.get();
    let mut uids: Vec<u32> = s.keys.values().map(|k| k.uid).filter(|u| *u != NO_ID).collect();
    uids.extend(s.users.iter().map(|u| u.uid));
    uids.sort_unstable();
    uids.dedup();
    let mut out = String::new();
    for uid in uids {
        let n = s.keys.values().filter(|k| k.uid == uid).count();
        let ni = s.keys.values().filter(|k| k.uid == uid && !k.negative()).count();
        let (qn, qb) = s.usage(uid);
        let (maxn, maxb) = Store::limits(uid);
        out.push_str(&format!(
            "{:5}: {:5} {}/{} {}/{} {}/{}\n",
            to_ns_id(uid, false),
            n,
            n,
            ni,
            qn,
            maxn,
            qb,
            maxb
        ));
    }
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller() -> Caller {
        Caller {
            pid: 1,
            start: 1,
            tid: 1,
            uid: 1000,
            gid: 1000,
            groups: vec![1000],
            admin: false,
            setuid: false,
            userns: Vec::new(),
        }
    }

    fn ring(s: &mut Store, c: &Caller, desc: &[u8]) -> i32 {
        let perm = (KEY_ALL << KEY_POS_SHIFT) | (KEY_VIEW << KEY_USR_SHIFT);
        s.alloc("keyring", desc, c.uid, c.gid, perm, 0, Vec::new(), false).unwrap()
    }

    fn user(s: &mut Store, c: &Caller, desc: &[u8]) -> i32 {
        let perm = (KEY_ALL << KEY_POS_SHIFT) | (KEY_VIEW << KEY_USR_SHIFT);
        s.alloc("user", desc, c.uid, c.gid, perm, 0, b"x".to_vec(), false).unwrap()
    }

    /// A key linked twice is linked once; a keyring that would contain
    /// itself is refused; a key of the same type and description displaces
    /// the one there.
    #[test]
    fn links_refuse_cycles_and_displace() {
        let c = caller();
        let mut s = Store::default();
        let (a, b) = (ring(&mut s, &c, b"a"), ring(&mut s, &c, b"b"));
        let k = user(&mut s, &c, b"k");
        s.link(a, k).unwrap();
        s.link(a, k).unwrap();
        assert_eq!(s.keys[&a].links, vec![k]);
        s.link(a, b).unwrap();
        assert_eq!(s.link(b, a), Err(errno::EDEADLK));
        assert_eq!(s.link(a, a), Err(errno::EDEADLK));
        assert_eq!(s.link(k, a), Err(errno::ENOTDIR));
        let k2 = user(&mut s, &c, b"k");
        s.link(a, k2).unwrap();
        assert_eq!(s.keys[&a].links, vec![b, k2]);
    }

    /// The process keyring is made on demand; what it links is possessed,
    /// found by a search, and reported revoked once revoked.
    #[test]
    fn process_keyring_search_and_possession() {
        let c = caller();
        let mut s = Store::default();
        assert_eq!(s.lookup(&c, KEY_SPEC_PROCESS_KEYRING, Look::PLAIN, 0), Err(errno::ENOKEY));
        let (p, possessed) = s.lookup(&c, KEY_SPEC_PROCESS_KEYRING, Look::CREATE, 0).unwrap();
        assert!(possessed);
        let k = user(&mut s, &c, b"k");
        s.link(p, k).unwrap();
        assert!(s.possessed(&c).contains(&k));
        assert_eq!(s.search_process(&c, "user", b"k"), Ok(k));
        assert_eq!(s.search_process(&c, "user", b"other"), Err(errno::ENOKEY));
        s.keys.get_mut(&k).unwrap().flags |= REVOKED;
        assert_eq!(s.search_process(&c, "user", b"k"), Err(errno::EKEYREVOKED));
    }

    /// A key no keyring links and no process holds is collected; one the
    /// user keyring links stays.
    #[test]
    fn unreachable_keys_go() {
        let c = caller();
        let mut s = Store::default();
        let u = s.user_rings(c.uid);
        let kept = user(&mut s, &c, b"kept");
        s.link(u.user, kept).unwrap();
        let lost = user(&mut s, &c, b"lost");
        s.collect();
        assert!(s.keys.contains_key(&kept));
        assert!(!s.keys.contains_key(&lost));
        // The user-session keyring links the user keyring.
        assert!(s.keys[&u.session].links.contains(&u.user));
    }

    /// Without the user's permission a key is still the possessor's to use.
    #[test]
    fn possessor_permissions_add_to_the_user_s() {
        let c = caller();
        let mut s = Store::default();
        let (p, _) = s.lookup(&c, KEY_SPEC_PROCESS_KEYRING, Look::CREATE, 0).unwrap();
        let k = user(&mut s, &c, b"k");
        s.keys.get_mut(&k).unwrap().perm = KEY_ALL << KEY_POS_SHIFT;
        assert_eq!(s.lookup(&c, k, Look::PLAIN, KEY_VIEW), Err(errno::EACCES));
        s.link(p, k).unwrap();
        assert_eq!(s.lookup(&c, k, Look::PLAIN, KEY_VIEW), Ok((k, true)));
    }

    /// A keyring's restriction keeps the key it trusts, though nothing
    /// else links it.
    #[test]
    fn a_restriction_keeps_its_signer() {
        let c = caller();
        let mut s = Store::default();
        let u = s.user_rings(c.uid);
        let r = ring(&mut s, &c, b"restricted");
        s.link(u.user, r).unwrap();
        let signer = user(&mut s, &c, b"signer");
        s.keys.get_mut(&r).unwrap().restrict = Restrict::KeyOrKeyring(signer, false);
        s.collect();
        assert!(s.keys.contains_key(&signer));
    }

    /// A negative key fails a full lookup with its error; a partial one
    /// finds it. A revoked key fails a partial lookup, and a revoked
    /// keyring takes no link.
    #[test]
    fn lookups_check_the_key_s_state() {
        let c = caller();
        let mut s = Store::default();
        let (p, _) = s.lookup(&c, KEY_SPEC_PROCESS_KEYRING, Look::CREATE, 0).unwrap();
        let k = user(&mut s, &c, b"k");
        s.link(p, k).unwrap();
        s.keys.get_mut(&k).unwrap().flags |= NEGATIVE;
        s.keys.get_mut(&k).unwrap().reject = errno::EKEYREJECTED;
        assert_eq!(s.lookup(&c, k, Look::PLAIN, KEY_VIEW), Err(errno::EKEYREJECTED));
        assert!(s.lookup(&c, k, Look::PARTIAL, KEY_VIEW).is_ok());
        let k2 = user(&mut s, &c, b"k2");
        s.link(p, k2).unwrap();
        s.keys.get_mut(&k2).unwrap().flags |= REVOKED;
        assert_eq!(s.lookup(&c, k2, Look::PARTIAL, KEY_VIEW), Err(errno::EKEYREVOKED));
        s.keys.get_mut(&p).unwrap().flags |= REVOKED;
        let k3 = user(&mut s, &c, b"k3");
        assert_eq!(s.link(p, k3), Err(errno::EKEYREVOKED));
    }

    /// Each link costs its keyring's owner bytes of their quota.
    #[test]
    fn links_are_charged() {
        let c = caller();
        let mut s = Store::default();
        let r = ring(&mut s, &c, b"r");
        let (_, before) = s.usage(c.uid);
        let k = user(&mut s, &c, b"k");
        let (_, with_key) = s.usage(c.uid);
        s.link(r, k).unwrap();
        assert_eq!(s.usage(c.uid).1, with_key + LINK_BYTES);
        assert!(with_key > before);
    }

    /// The store survives its encoding.
    #[test]
    fn store_round_trips() {
        let c = caller();
        let mut s = Store::default();
        let (p, _) = s.lookup(&c, KEY_SPEC_PROCESS_KEYRING, Look::CREATE, 0).unwrap();
        let k = user(&mut s, &c, b"k");
        s.link(p, k).unwrap();
        s.keys.get_mut(&p).unwrap().restrict = Restrict::KeyOrKeyring(k, true);
        let mut e = Enc::new();
        s.encode(&mut e);
        let bytes = e.into_bytes();
        let back = Store::decode(&mut Dec::new(&bytes));
        assert_eq!(back.keys, s.keys);
        assert_eq!(back.holders, s.holders);
    }
}
