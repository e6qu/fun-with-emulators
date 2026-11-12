//! System V IPC: shared memory segments, semaphore sets and message queues,
//! one set of each per IPC namespace, shared by every process in it.
//!
//! A namespace's objects are its record's data ([`crate::shared::Record`],
//! the namespace's own record, or for the initial namespace a named one):
//! each object's key, owner, permissions and times, a semaphore set's
//! values and undo adjustments, a queue's messages. A segment's memory is
//! a file beside the record, which `shmat` maps shared. Every operation is
//! one change of the record, under its lock, so a semaphore operation or a
//! message is all or nothing across processes; an operation that must wait
//! (a semaphore that would go below zero, a full or empty queue) waits for
//! the record to change and tries again.
//!
//! A process is known by pid and start time. What one that has gone (even
//! killed) leaves — its attachments, its `SEM_UNDO` adjustments — is
//! cleaned up by the next process that looks, as Linux does when it ends:
//! a segment marked for removal goes with its last attachment.

use crate::shared::{Data, Record};
use crate::snapshot::{Dec, Enc};
use fwe_abi::errno;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::{Arc, Mutex};

// `ipc.h`, `shm.h`, `sem.h`, `msg.h`.
pub const IPC_PRIVATE: i32 = 0;
pub const IPC_CREAT: u64 = 0o1000;
pub const IPC_EXCL: u64 = 0o2000;
pub const IPC_NOWAIT: u64 = 0o4000;
pub const IPC_RMID: u64 = 0;
pub const IPC_SET: u64 = 1;
pub const IPC_STAT: u64 = 2;
pub const IPC_INFO: u64 = 3;
/// `IPC_64`, which arm64's C libraries set in a command (every arm64
/// structure is the 64-bit one).
const IPC_64: u64 = 0x100;
pub const SHM_LOCK: u64 = 11;
pub const SHM_UNLOCK: u64 = 12;
pub const SHM_STAT: u64 = 13;
pub const SHM_INFO: u64 = 14;
pub const SHM_STAT_ANY: u64 = 15;
pub const SHM_RDONLY: u64 = 0o10000;
pub const SHM_HUGETLB: u64 = 0o4000;
pub const SHM_RND: u64 = 0o20000;
pub const SHM_REMAP: u64 = 0o40000;
pub const SHM_EXEC: u64 = 0o100000;
/// Mode bits Linux shows: marked for removal, locked.
const SHM_DEST: u32 = 0o1000;
const SHM_LOCKED: u32 = 0o2000;
pub const GETPID: u64 = 11;
pub const GETVAL: u64 = 12;
pub const GETALL: u64 = 13;
pub const GETNCNT: u64 = 14;
pub const GETZCNT: u64 = 15;
pub const SETVAL: u64 = 16;
pub const SETALL: u64 = 17;
pub const SEM_STAT: u64 = 18;
pub const SEM_INFO: u64 = 19;
pub const SEM_STAT_ANY: u64 = 20;
pub const SEM_UNDO: i16 = 0x1000;
pub const MSG_STAT: u64 = 11;
pub const MSG_INFO: u64 = 12;
pub const MSG_STAT_ANY: u64 = 13;
pub const MSG_NOERROR: u64 = 0o10000;
pub const MSG_EXCEPT: u64 = 0o20000;
pub const MSG_COPY: u64 = 0o40000;

// Linux's limits (its defaults).
const IPCMNI: i32 = 32768;
pub const SHMMIN: u64 = 1;
pub const SHMMAX: u64 = u64::MAX - (1 << 24);
pub const SHMALL: u64 = u64::MAX - (1 << 24);
pub const SHMMNI: u64 = 4096;
pub const SEMMSL: i32 = 32000;
pub const SEMMNS: i32 = 1_024_000_000;
pub const SEMOPM: i32 = 500;
pub const SEMMNI: i32 = 32000;
pub const SEMVMX: i32 = 32767;
pub const SEMAEM: i32 = SEMVMX;
pub const MSGMAX: u64 = 8192;
pub const MSGMNB: u64 = 16384;
pub const MSGMNI: u64 = 32000;
/// `SHMLBA` on arm64: four pages.
pub const SHMLBA: u64 = 4 * 4096;

/// A process, by host pid and start time.
pub type Proc = (i32, u64);

/// This process.
pub fn me() -> Proc {
    static ME: Mutex<Proc> = Mutex::new((0, 0));
    // SAFETY: getpid cannot fail.
    let pid = unsafe { libc::getpid() };
    let mut m = ME.lock().unwrap_or_else(|e| e.into_inner());
    if m.0 != pid {
        *m = (pid, crate::procreg::start_time(pid).unwrap_or(0));
    }
    *m
}

fn alive(p: Proc) -> bool {
    p == me() || crate::procreg::alive(p)
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// The three kinds, each with its own ids.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    Shm = 0,
    Sem = 1,
    Msg = 2,
}

/// `struct ipc64_perm`'s owner and mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Perm {
    pub uid: u32,
    pub gid: u32,
    pub cuid: u32,
    pub cgid: u32,
    pub mode: u32,
}

#[derive(Clone, Debug, Default)]
pub struct Shm {
    pub size: u64,
    pub cpid: i32,
    pub lpid: i32,
    pub atime: i64,
    pub dtime: i64,
    /// Attachments, by process.
    pub attached: Vec<(Proc, u32)>,
    pub locked: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Sem {
    pub otime: i64,
    /// Each semaphore's value and the pid of the last process that operated
    /// on it.
    pub vals: Vec<(i32, i32)>,
    /// Processes waiting: (process, semaphore, for zero).
    pub waiting: Vec<(Proc, u16, bool)>,
    /// `SEM_UNDO` adjustments, by process: (semaphore, adjustment).
    pub undo: Vec<(Proc, Vec<(u16, i32)>)>,
}

#[derive(Clone, Debug, Default)]
pub struct Msg {
    pub stime: i64,
    pub rtime: i64,
    pub qbytes: u64,
    pub lspid: i32,
    pub lrpid: i32,
    pub msgs: VecDeque<(i64, Vec<u8>)>,
}

#[derive(Clone, Debug)]
pub enum Body {
    Shm(Shm),
    Sem(Sem),
    Msg(Msg),
}

#[derive(Clone, Debug)]
pub struct Obj {
    pub key: i32,
    pub perm: Perm,
    pub ctime: i64,
    /// A segment marked for removal (`IPC_RMID` while attached): its key
    /// is no longer found, and it goes with its last attachment.
    pub removed: bool,
    pub body: Body,
}

impl Obj {
    pub fn kind(&self) -> Kind {
        match self.body {
            Body::Shm(_) => Kind::Shm,
            Body::Sem(_) => Kind::Sem,
            Body::Msg(_) => Kind::Msg,
        }
    }
}

/// A namespace's objects.
#[derive(Clone, Debug, Default)]
pub struct Ipc {
    /// By kind and id.
    pub objs: Tracked<(u8, i32), Obj>,
    /// Each kind's slots' sequence numbers (an id is the slot and the
    /// sequence, so one reused is a new id).
    pub seqs: Tracked<(u8, i32), u16>,
    /// The namespace's sysctls (`kernel.shmmax` and the like) set from
    /// their defaults, by name ([`crate::sysctl`]).
    pub sysctls: BTreeMap<String, String>,
    /// The namespace's POSIX message queues ([`crate::mqueue`]): each
    /// name's queue, by its record's directory in this one's.
    pub mq_names: BTreeMap<Vec<u8>, Vec<u8>>,
    /// Every queue not yet freed (one unlinked lives while it is open),
    /// with the user it is charged to and the bytes charged
    /// (`RLIMIT_MSGQUEUE`).
    pub mq_live: BTreeMap<Vec<u8>, (u32, u64)>,
    /// The number the next queue's directory takes.
    pub mq_seq: u64,
    /// What finds objects without looking at each: kept up to date from
    /// the objects changed since it last looked, not recorded.
    index: Lazy,
}

/// The objects by key, the slots in use, and those that hold processes.
#[derive(Clone, Debug, Default)]
struct Index {
    /// (kind, key) to id, of objects with a key not marked for removal.
    by_key: HashMap<(u8, i32), i32>,
    /// (kind, id) to the key it is found by above.
    key_of: HashMap<(u8, i32), i32>,
    /// (kind, slot) to the id in it.
    slots: HashMap<(u8, i32), i32>,
    /// Each kind's count of slots in use, and the lowest that may be free.
    used: [(usize, i32); 3],
    /// Objects that name processes (attachments, waiters, undo
    /// adjustments) or are marked for removal: what [`Ipc::reap`] looks at.
    holders: BTreeSet<(u8, i32)>,
}

/// An [`Index`] that reading data may bring up to date.
#[derive(Debug, Default)]
struct Lazy(Mutex<Index>);

impl Clone for Lazy {
    fn clone(&self) -> Self {
        Lazy(Mutex::new(self.0.lock().unwrap_or_else(|e| e.into_inner()).clone()))
    }
}

impl Index {
    /// Object `(kind, id)` is now `o` (or gone).
    fn reindex(&mut self, kind: u8, id: i32, o: Option<&Obj>) {
        if let Some(key) = self.key_of.remove(&(kind, id))
            && self.by_key.get(&(kind, key)) == Some(&id)
        {
            self.by_key.remove(&(kind, key));
        }
        self.holders.remove(&(kind, id));
        let slot = (kind, id % IPCMNI);
        let used = &mut self.used[kind as usize % 3];
        match o {
            Some(o) => {
                if self.slots.insert(slot, id).is_none() {
                    used.0 += 1;
                }
                if o.key != IPC_PRIVATE && !o.removed {
                    self.by_key.insert((kind, o.key), id);
                    self.key_of.insert((kind, id), o.key);
                }
                let holds = o.removed
                    || match &o.body {
                        Body::Shm(s) => !s.attached.is_empty(),
                        Body::Sem(s) => !s.waiting.is_empty() || !s.undo.is_empty(),
                        Body::Msg(_) => false,
                    };
                if holds {
                    self.holders.insert((kind, id));
                }
            }
            None => {
                if self.slots.get(&slot) == Some(&id) {
                    self.slots.remove(&slot);
                    used.0 -= 1;
                    used.1 = used.1.min(slot.1);
                }
            }
        }
    }
}

impl Ipc {
    /// Sysctl `name`'s `i`th number, or `default`.
    fn tunable(&self, name: &str, i: usize, default: u64) -> u64 {
        self.sysctls
            .get(name)
            .and_then(|v| v.split_whitespace().nth(i))
            .and_then(|w| w.parse().ok())
            .unwrap_or(default)
    }

    pub fn shmmax(&self) -> u64 {
        self.tunable("kernel/shmmax", 0, SHMMAX)
    }

    pub fn shmall(&self) -> u64 {
        self.tunable("kernel/shmall", 0, SHMALL)
    }

    pub fn shmmni(&self) -> u64 {
        self.tunable("kernel/shmmni", 0, SHMMNI)
    }

    /// `kernel.sem`: the most semaphores a set, in all, operations a call,
    /// sets.
    pub fn sem(&self) -> [i32; 4] {
        let d = [SEMMSL, SEMMNS, SEMOPM, SEMMNI];
        std::array::from_fn(|i| self.tunable("kernel/sem", i, d[i] as u64) as i32)
    }

    pub fn msgmax(&self) -> u64 {
        self.tunable("kernel/msgmax", 0, MSGMAX)
    }

    pub fn msgmnb(&self) -> u64 {
        self.tunable("kernel/msgmnb", 0, MSGMNB)
    }

    pub fn msgmni(&self) -> u64 {
        self.tunable("kernel/msgmni", 0, MSGMNI)
    }

    /// `fs.mqueue.*`: the most queues, the largest `mq_maxmsg` and
    /// `mq_msgsize` an unprivileged creator may ask, and a queue's when it
    /// asks none.
    pub fn mq_tunable(&self, name: &str) -> i64 {
        use fwe_abi::mqueue as mq;
        let default = match name {
            "queues_max" => mq::DFLT_QUEUESMAX,
            "msg_max" => mq::DFLT_MSGMAX,
            "msgsize_max" => mq::DFLT_MSGSIZEMAX,
            "msg_default" => mq::DFLT_MSG,
            _ => mq::DFLT_MSGSIZE,
        };
        self.tunable(&format!("fs/mqueue/{name}"), 0, default as u64) as i64
    }
}

fn put_perm(e: &mut Enc, p: &Perm) {
    for v in [p.uid, p.gid, p.cuid, p.cgid, p.mode] {
        e.u32(v);
    }
}

fn get_perm(d: &mut Dec) -> Perm {
    Perm { uid: d.u32(), gid: d.u32(), cuid: d.u32(), cgid: d.u32(), mode: d.u32() }
}

fn put_proc(e: &mut Enc, p: Proc) {
    e.i32(p.0);
    e.u64(p.1);
}

fn get_proc(d: &mut Dec) -> Proc {
    (d.i32(), d.u64())
}

fn put_obj(e: &mut Enc, id: i32, o: &Obj) {
    e.i32(id);
    e.i32(o.key);
    put_perm(e, &o.perm);
    e.u64(o.ctime as u64);
    e.bool(o.removed);
    match &o.body {
        Body::Shm(s) => {
            e.u8(0);
            e.u64(s.size);
            e.i32(s.cpid);
            e.i32(s.lpid);
            e.u64(s.atime as u64);
            e.u64(s.dtime as u64);
            e.bool(s.locked);
            e.u64(s.attached.len() as u64);
            for &(p, n) in &s.attached {
                put_proc(e, p);
                e.u32(n);
            }
        }
        Body::Sem(s) => {
            e.u8(1);
            e.u64(s.otime as u64);
            e.u64(s.vals.len() as u64);
            for &(v, pid) in &s.vals {
                e.i32(v);
                e.i32(pid);
            }
            e.u64(s.waiting.len() as u64);
            for &(p, n, z) in &s.waiting {
                put_proc(e, p);
                e.u32(n as u32);
                e.bool(z);
            }
            e.u64(s.undo.len() as u64);
            for (p, adj) in &s.undo {
                put_proc(e, *p);
                e.u64(adj.len() as u64);
                for &(n, a) in adj {
                    e.u32(n as u32);
                    e.i32(a);
                }
            }
        }
        Body::Msg(m) => {
            e.u8(2);
            e.u64(m.stime as u64);
            e.u64(m.rtime as u64);
            e.u64(m.qbytes);
            e.i32(m.lspid);
            e.i32(m.lrpid);
            e.u64(m.msgs.len() as u64);
            for (t, text) in &m.msgs {
                e.u64(*t as u64);
                e.bytes(text);
            }
        }
    }
}

fn get_obj(d: &mut Dec) -> (i32, Obj) {
    let (id, key, perm, ctime, removed) = (d.i32(), d.i32(), get_perm(d), d.u64() as i64, d.bool());
    let body = match d.u8() {
        0 => {
            let (size, cpid, lpid, atime, dtime, locked) =
                (d.u64(), d.i32(), d.i32(), d.u64() as i64, d.u64() as i64, d.bool());
            let n = d.count(16);
            let attached = (0..n).map(|_| (get_proc(d), d.u32())).collect();
            Body::Shm(Shm { size, cpid, lpid, atime, dtime, attached, locked })
        }
        1 => {
            let otime = d.u64() as i64;
            let n = d.count(8);
            let vals = (0..n).map(|_| (d.i32(), d.i32())).collect();
            let n = d.count(17);
            let waiting = (0..n).map(|_| (get_proc(d), d.u32() as u16, d.bool())).collect();
            let n = d.count(20);
            let undo = (0..n)
                .map(|_| {
                    let p = get_proc(d);
                    let m = d.count(8);
                    (p, (0..m).map(|_| (d.u32() as u16, d.i32())).collect())
                })
                .collect();
            Body::Sem(Sem { otime, vals, waiting, undo })
        }
        _ => {
            let (stime, rtime, qbytes, lspid, lrpid) =
                (d.u64() as i64, d.u64() as i64, d.u64(), d.i32(), d.i32());
            let n = d.count(16);
            let msgs = (0..n).map(|_| (d.u64() as i64, d.bytes())).collect();
            Body::Msg(Msg { stime, rtime, qbytes, lspid, lrpid, msgs })
        }
    };
    (id, Obj { key, perm, ctime, removed, body })
}

impl Ipc {
    /// What is small and kept whole, in a change as in the data: the
    /// sysctls and the POSIX message queues.
    fn put_rest(&self, e: &mut Enc) {
        e.u64(self.sysctls.len() as u64);
        for (k, v) in &self.sysctls {
            e.bytes(k.as_bytes());
            e.bytes(v.as_bytes());
        }
        e.u64(self.mq_names.len() as u64);
        for (name, dir) in &self.mq_names {
            e.bytes(name);
            e.bytes(dir);
        }
        e.u64(self.mq_live.len() as u64);
        for (dir, &(uid, bytes)) in &self.mq_live {
            e.bytes(dir);
            e.u32(uid);
            e.u64(bytes);
        }
        e.u64(self.mq_seq);
    }

    fn get_rest(&mut self, d: &mut Dec) {
        self.sysctls.clear();
        let n = d.count(16);
        for _ in 0..n {
            let (k, v) = (d.bytes(), d.bytes());
            self.sysctls.insert(
                String::from_utf8_lossy(&k).into_owned(),
                String::from_utf8_lossy(&v).into_owned(),
            );
        }
        self.mq_names.clear();
        let n = d.count(16);
        for _ in 0..n {
            let (name, dir) = (d.bytes(), d.bytes());
            self.mq_names.insert(name, dir);
        }
        self.mq_live.clear();
        let n = d.count(20);
        for _ in 0..n {
            let (dir, uid, bytes) = (d.bytes(), d.u32(), d.u64());
            self.mq_live.insert(dir, (uid, bytes));
        }
        self.mq_seq = d.u64();
    }
}

impl Data for Ipc {
    fn encode(&self, e: &mut Enc) {
        self.put_rest(e);
        e.u64(self.seqs.len() as u64);
        for (&(k, slot), &seq) in self.seqs.iter() {
            e.u8(k);
            e.i32(slot);
            e.u32(seq as u32);
        }
        e.u64(self.objs.len() as u64);
        for (&(_, id), o) in self.objs.iter() {
            put_obj(e, id, o);
        }
    }

    fn decode(d: &mut Dec) -> Self {
        let mut ipc = Ipc::default();
        ipc.get_rest(d);
        let n = d.count(9);
        for _ in 0..n {
            let (k, slot, seq) = (d.u8(), d.i32(), d.u32() as u16);
            ipc.seqs.set((k, slot), Some(seq));
        }
        let n = d.count(30);
        for _ in 0..n {
            let (id, obj) = get_obj(d);
            ipc.objs.set((obj.kind() as u8, id), Some(obj));
        }
        ipc
    }

    /// The objects and slots changed, each as it is now (or gone), with
    /// the rest whole.
    fn changes(&mut self, e: &mut Enc) -> bool {
        self.put_rest(e);
        let seqs = self.seqs.take_changed();
        e.u64(seqs.len() as u64);
        for (k, slot) in seqs {
            e.u8(k);
            e.i32(slot);
            match self.seqs.get(&(k, slot)) {
                Some(&seq) => {
                    e.bool(true);
                    e.u32(seq as u32);
                }
                None => e.bool(false),
            }
        }
        let objs = self.objs.take_changed();
        e.u64(objs.len() as u64);
        for (k, id) in objs {
            e.u8(k);
            match self.objs.get(&(k, id)) {
                Some(o) => {
                    e.bool(true);
                    put_obj(e, id, o);
                }
                None => {
                    e.bool(false);
                    e.i32(id);
                }
            }
        }
        true
    }

    fn apply(&mut self, d: &mut Dec) {
        self.get_rest(d);
        let n = d.count(6);
        for _ in 0..n {
            let (k, slot) = (d.u8(), d.i32());
            let seq = d.bool().then(|| d.u32() as u16);
            self.seqs.set((k, slot), seq);
        }
        let n = d.count(6);
        for _ in 0..n {
            let k = d.u8();
            if d.bool() {
                let (id, o) = get_obj(d);
                self.objs.set((k, id), Some(o));
            } else {
                let id = d.i32();
                self.objs.set((k, id), None);
            }
        }
    }
}

/// A map that keeps which keys changed since it was last asked
/// ([`Tracked::take_changed`]): what a record's change holds.
#[derive(Debug)]
pub struct Tracked<K, V> {
    map: BTreeMap<K, V>,
    changed: BTreeSet<K>,
    /// The keys set since an index over the map last looked
    /// ([`Tracked::take_unindexed`]).
    unindexed: Mutex<BTreeSet<K>>,
}

impl<K, V> Default for Tracked<K, V> {
    fn default() -> Self {
        Tracked { map: BTreeMap::new(), changed: BTreeSet::new(), unindexed: Mutex::default() }
    }
}

impl<K: Clone, V: Clone> Clone for Tracked<K, V> {
    fn clone(&self) -> Self {
        Tracked {
            map: self.map.clone(),
            changed: self.changed.clone(),
            unindexed: Mutex::new(self.unindexed.lock().unwrap_or_else(|e| e.into_inner()).clone()),
        }
    }
}

impl<K: Ord + Clone, V> Tracked<K, V> {
    /// `k` changed: for the record's change, and for indexes.
    fn mark(&mut self, k: &K) {
        self.changed.insert(k.clone());
        self.unindexed.get_mut().unwrap_or_else(|e| e.into_inner()).insert(k.clone());
    }
    pub fn get(&self, k: &K) -> Option<&V> {
        self.map.get(k)
    }
    /// The value at `k`, to change: `k` counts as changed.
    pub fn get_mut(&mut self, k: &K) -> Option<&mut V> {
        if !self.map.contains_key(k) {
            return None;
        }
        self.mark(k);
        self.map.get_mut(k)
    }
    pub fn insert(&mut self, k: K, v: V) -> Option<V> {
        self.mark(&k);
        self.map.insert(k, v)
    }
    pub fn remove(&mut self, k: &K) -> Option<V> {
        let v = self.map.remove(k)?;
        self.mark(k);
        Some(v)
    }
    pub fn contains_key(&self, k: &K) -> bool {
        self.map.contains_key(k)
    }
    pub fn len(&self) -> usize {
        self.map.len()
    }
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
    pub fn iter(&self) -> std::collections::btree_map::Iter<'_, K, V> {
        self.map.iter()
    }
    pub fn keys(&self) -> std::collections::btree_map::Keys<'_, K, V> {
        self.map.keys()
    }
    pub fn values(&self) -> std::collections::btree_map::Values<'_, K, V> {
        self.map.values()
    }
    pub fn range<R: std::ops::RangeBounds<K>>(
        &self,
        r: R,
    ) -> std::collections::btree_map::Range<'_, K, V> {
        self.map.range(r)
    }
    /// Run `f` on each entry: those it says it changed count as changed.
    pub fn each_mut(&mut self, mut f: impl FnMut(&K, &mut V) -> bool) {
        let unindexed = self.unindexed.get_mut().unwrap_or_else(|e| e.into_inner());
        for (k, v) in self.map.iter_mut() {
            if f(k, v) {
                self.changed.insert(k.clone());
                unindexed.insert(k.clone());
            }
        }
    }
    /// Set `k` to `v` (or none) without counting it as changed: for data
    /// read, or changes applied.
    pub fn set(&mut self, k: K, v: Option<V>) {
        self.unindexed.get_mut().unwrap_or_else(|e| e.into_inner()).insert(k.clone());
        match v {
            Some(v) => self.map.insert(k, v),
            None => self.map.remove(&k),
        };
    }
    /// The keys changed since last asked.
    pub fn take_changed(&mut self) -> Vec<K> {
        std::mem::take(&mut self.changed).into_iter().collect()
    }
    /// The keys set since an index last asked.
    fn take_unindexed(&self) -> BTreeSet<K> {
        std::mem::take(&mut *self.unindexed.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

impl<K: Ord + Clone, V> std::ops::Index<&K> for Tracked<K, V> {
    type Output = V;
    fn index(&self, k: &K) -> &V {
        &self.map[k]
    }
}

/// The initial IPC namespace's objects. Like Linux's, they last until the
/// machine restarts: the record is the host boot's.
pub fn initial() -> Option<Arc<Record<Ipc>>> {
    static INITIAL: Mutex<Option<Arc<Record<Ipc>>>> = Mutex::new(None);
    let mut g = INITIAL.lock().unwrap_or_else(|e| e.into_inner());
    if g.is_none() {
        let name = format!("ipc-initial-{}", crate::host::boot_time());
        *g = Record::named(&name, crate::ns::INIT_IPC, Ipc::default).ok().map(Arc::new);
    }
    g.clone()
}

/// The process's IPC namespace (`None` until it is set: the initial one).
pub(crate) static CURRENT: Mutex<Option<Arc<Record<Ipc>>>> = Mutex::new(None);

/// The process's namespaces are now these: its IPC namespace's record
/// (the initial namespace's for `None`).
pub fn activate(ipc: Option<Arc<Record<Ipc>>>) {
    *CURRENT.lock().unwrap_or_else(|e| e.into_inner()) = ipc;
}

/// This process has used System V IPC (so has something to leave as it
/// ends: undo adjustments, attachments).
static USED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn set_current(r: &Arc<Record<Ipc>>) {
    USED.store(true, std::sync::atomic::Ordering::Relaxed);
    let mut g = CURRENT.lock().unwrap_or_else(|e| e.into_inner());
    if !g.as_ref().is_some_and(|c| Arc::ptr_eq(c, r)) {
        *g = Some(r.clone());
    }
}

thread_local! {
    /// This thread's own IPC namespace, when it has its own
    /// ([`crate::threadfs`]): `Some(None)` for the initial one.
    static THREAD: std::cell::RefCell<Option<Option<Arc<Record<Ipc>>>>> =
        const { std::cell::RefCell::new(None) };
}

/// Make `ipc` this thread's own (`Some`), or the process's again (`None`).
pub fn set_thread(ipc: Option<Option<Arc<Record<Ipc>>>>) {
    THREAD.with(|t| *t.borrow_mut() = ipc);
}

/// The calling thread's IPC namespace's objects.
pub fn current() -> Option<Arc<Record<Ipc>>> {
    if let Some(own) = THREAD.with(|t| t.borrow().clone()) {
        return own.or_else(initial);
    }
    CURRENT.lock().unwrap_or_else(|e| e.into_inner()).clone().or_else(initial)
}

/// The file of segment `id` in namespace record `r`.
pub fn segment_path(r: &Record<Ipc>, id: i32) -> Vec<u8> {
    [r.dir(), format!("/shm-{id}").as_bytes()].concat()
}

fn remove_segment_file(r: &Record<Ipc>, id: i32) {
    if let Ok(p) = std::ffi::CString::new(segment_path(r, id)) {
        // SAFETY: a NUL-terminated path in fwe's private directory.
        unsafe { libc::unlink(p.as_ptr()) };
    }
}

impl Ipc {
    /// Make an object of `kind` with `key`: its id (`ENOSPC` past the
    /// kind's limit).
    pub fn create(
        &mut self,
        kind: Kind,
        key: i32,
        perm: Perm,
        body: Body,
        limit: usize,
    ) -> Result<i32, i32> {
        // An id asked for (`kernel.*_next_id`, used once): its slot, or
        // the first free one past it, with its sequence number.
        let next_name = match kind {
            Kind::Shm => "kernel/shm_next_id",
            Kind::Sem => "kernel/sem_next_id",
            Kind::Msg => "kernel/msg_next_id",
        };
        let asked = self.sysctls.get(next_name).and_then(|v| v.trim().parse::<i32>().ok());
        let asked = asked.filter(|&v| v >= 0);
        let slot = {
            let mut idx = self.index();
            let k = kind as u8;
            if idx.used[k as usize % 3].0 >= limit {
                return Err(errno::ENOSPC);
            }
            match asked {
                Some(v) => (v % IPCMNI..IPCMNI)
                    .find(|&s| !idx.slots.contains_key(&(k, s)))
                    .ok_or(errno::ENOSPC)?,
                None => {
                    let from = idx.used[k as usize % 3].1;
                    let slot = (from..IPCMNI)
                        .find(|&s| !idx.slots.contains_key(&(k, s)))
                        .ok_or(errno::ENOSPC)?;
                    // The slots below it are all in use.
                    idx.used[k as usize % 3].1 = slot + 1;
                    slot
                }
            }
        };
        let seq = match asked {
            Some(v) => {
                self.sysctls.remove(next_name);
                (v / IPCMNI) as u16
            }
            None => self.seqs.get(&(kind as u8, slot)).copied().unwrap_or(0),
        };
        let id = seq as i32 * IPCMNI + slot;
        self.seqs.insert((kind as u8, slot), seq.wrapping_add(1) % (i32::MAX / IPCMNI) as u16);
        self.objs.insert((kind as u8, id), Obj { key, perm, ctime: now(), removed: false, body });
        Ok(id)
    }

    /// The object of `kind` with `key` (not one marked for removal).
    pub fn by_key(&self, kind: Kind, key: i32) -> Option<i32> {
        if key == IPC_PRIVATE {
            return self
                .objs
                .iter()
                .find(|(_, o)| o.kind() == kind && o.key == key && !o.removed)
                .map(|(&(_, id), _)| id);
        }
        self.index().by_key.get(&(kind as u8, key)).copied()
    }

    /// The index, brought up to date with the objects changed since it
    /// last looked.
    fn index(&self) -> std::sync::MutexGuard<'_, Index> {
        let mut idx = self.index.0.lock().unwrap_or_else(|e| e.into_inner());
        for (kind, id) in self.objs.take_unindexed() {
            idx.reindex(kind, id, self.objs.get(&(kind, id)));
        }
        idx
    }

    /// The object of `kind` with id `id`.
    pub fn get(&mut self, kind: Kind, id: i32) -> Result<&mut Obj, i32> {
        if id < 0 {
            return Err(errno::EINVAL);
        }
        self.objs.get_mut(&(kind as u8, id)).ok_or(errno::EINVAL)
    }

    /// The object of `kind` in slot `index` (`*_STAT`): its id.
    pub fn by_index(&self, kind: Kind, index: i32) -> Option<i32> {
        self.objs
            .keys()
            .find(|&&(k, id)| k == kind as u8 && id % IPCMNI == index)
            .map(|&(_, id)| id)
    }

    /// The highest slot of `kind` in use (`*_INFO` returns it).
    pub fn highest(&self, kind: Kind) -> i32 {
        self.objs
            .keys()
            .filter(|&&(k, _)| k == kind as u8)
            .map(|&(_, id)| id % IPCMNI)
            .max()
            .unwrap_or(0)
    }

    pub fn count(&self, kind: Kind) -> usize {
        self.index().used[kind as usize % 3].0
    }

    /// What processes that have gone left: their attachments and undo
    /// adjustments (applied, as Linux applies them as a process ends), and
    /// a segment marked for removal whose last attachment that was.
    pub fn reap(&mut self, r: &Record<Ipc>) -> bool {
        let mut changed = false;
        let mut gone_segments = Vec::new();
        // Only objects that name processes, or are marked for removal.
        let holders: Vec<(u8, i32)> = self.index().holders.iter().copied().collect();
        for k in holders {
            let Some(o) = self.objs.get(&k) else { continue };
            let stale = match &o.body {
                Body::Shm(s) => {
                    (o.removed && s.attached.is_empty())
                        || s.attached.iter().any(|&(p, _)| !alive(p))
                }
                Body::Sem(s) => {
                    s.waiting.iter().any(|&(p, _, _)| !alive(p))
                        || s.undo.iter().any(|(p, _)| !alive(*p))
                }
                Body::Msg(_) => false,
            };
            let Some(o) = self.objs.get_mut(&k).filter(|_| stale) else { continue };
            match &mut o.body {
                Body::Shm(s) => {
                    s.attached.retain(|&(p, _)| alive(p));
                    if o.removed && s.attached.is_empty() {
                        gone_segments.push(k.1);
                    }
                }
                Body::Sem(s) => {
                    s.waiting.retain(|&(p, _, _)| alive(p));
                    let (gone, live): (Vec<_>, Vec<_>) =
                        std::mem::take(&mut s.undo).into_iter().partition(|(p, _)| !alive(*p));
                    s.undo = live;
                    for (_, adj) in gone {
                        apply_undo(s, &adj);
                    }
                }
                Body::Msg(_) => {}
            }
            changed = true;
        }
        for id in gone_segments {
            self.objs.remove(&(Kind::Shm as u8, id));
            remove_segment_file(r, id);
            changed = true;
        }
        changed
    }
}

/// Apply undo adjustments `adj` to set `s`, each value held in range.
fn apply_undo(s: &mut Sem, adj: &[(u16, i32)]) {
    for &(n, a) in adj {
        if let Some(v) = s.vals.get_mut(n as usize) {
            v.0 = (v.0 + a).clamp(0, SEMVMX);
        }
    }
}

/// Whether `creds` may access an object with permission `perm` for `want`
/// (`4` read, `2` write, both `6`): with `CAP_IPC_OWNER`, or by the owner's,
/// the group's or others' bits, as `ipcperms` checks.
pub fn permits(creds: &crate::creds::Creds, perm: &Perm, want: u32) -> bool {
    if want == 0 || creds.has(crate::caps::CAP_IPC_OWNER) {
        return true;
    }
    let shift = if creds.euid == perm.uid || creds.euid == perm.cuid {
        6
    } else if [perm.gid, perm.cgid].iter().any(|&g| g == creds.egid || creds.groups.contains(&g)) {
        3
    } else {
        0
    };
    (perm.mode >> shift) & want == want
}

/// Whether `creds` may change or remove an object (`IPC_SET`,
/// `IPC_RMID`): its owner or creator, or with `CAP_SYS_ADMIN`.
pub fn owns(creds: &crate::creds::Creds, perm: &Perm) -> bool {
    creds.euid == perm.uid || creds.euid == perm.cuid || creds.has(crate::caps::CAP_SYS_ADMIN)
}

/// A command with `IPC_64` taken off.
pub fn command(cmd: u64) -> u64 {
    cmd & !IPC_64
}

/// `struct ipc64_perm` (48 bytes) at the start of `b`.
pub fn write_perm(b: &mut [u8], key: i32, p: &Perm, id: i32) {
    b[0..4].copy_from_slice(&key.to_ne_bytes());
    for (i, v) in [p.uid, p.gid, p.cuid, p.cgid, p.mode].iter().enumerate() {
        b[4 + i * 4..8 + i * 4].copy_from_slice(&v.to_ne_bytes());
    }
    b[24..26].copy_from_slice(&((id / IPCMNI) as u16).to_ne_bytes());
}

/// The owner and mode `IPC_SET` gives, from a `struct ipc64_perm` at the
/// start of `b`: uid, gid and the permission bits.
pub fn read_set(b: &[u8], p: &mut Perm) {
    let u = |at: usize| u32::from_ne_bytes(b[at..at + 4].try_into().unwrap());
    p.uid = u(4);
    p.gid = u(8);
    p.mode = (p.mode & !0o777) | (u(20) & 0o777);
}

fn put_u64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_ne_bytes());
}

fn put_i32(b: &mut [u8], at: usize, v: i32) {
    b[at..at + 4].copy_from_slice(&v.to_ne_bytes());
}

/// `struct shmid64_ds` (112 bytes) of segment `o`.
pub fn shmid_ds(o: &Obj, id: i32) -> Vec<u8> {
    let mut b = vec![0u8; 112];
    let Body::Shm(s) = &o.body else { return b };
    let mut perm = o.perm;
    if o.removed {
        perm.mode |= SHM_DEST;
    }
    if s.locked {
        perm.mode |= SHM_LOCKED;
    }
    write_perm(&mut b, o.key, &perm, id);
    put_u64(&mut b, 48, s.size);
    put_u64(&mut b, 56, s.atime as u64);
    put_u64(&mut b, 64, s.dtime as u64);
    put_u64(&mut b, 72, o.ctime as u64);
    put_i32(&mut b, 80, guest_pid(s.cpid));
    put_i32(&mut b, 84, guest_pid(s.lpid));
    put_u64(&mut b, 88, s.attached.iter().map(|&(_, n)| n as u64).sum());
    b
}

/// `struct semid64_ds` (88 bytes) of set `o`.
pub fn semid_ds(o: &Obj, id: i32) -> Vec<u8> {
    let mut b = vec![0u8; 88];
    let Body::Sem(s) = &o.body else { return b };
    write_perm(&mut b, o.key, &o.perm, id);
    put_u64(&mut b, 48, s.otime as u64);
    put_u64(&mut b, 56, o.ctime as u64);
    put_u64(&mut b, 64, s.vals.len() as u64);
    b
}

/// `struct msqid64_ds` (120 bytes) of queue `o`.
pub fn msqid_ds(o: &Obj, id: i32) -> Vec<u8> {
    let mut b = vec![0u8; 120];
    let Body::Msg(m) = &o.body else { return b };
    write_perm(&mut b, o.key, &o.perm, id);
    put_u64(&mut b, 48, m.stime as u64);
    put_u64(&mut b, 56, m.rtime as u64);
    put_u64(&mut b, 64, o.ctime as u64);
    put_u64(&mut b, 72, m.msgs.iter().map(|(_, t)| t.len() as u64).sum());
    put_u64(&mut b, 80, m.msgs.len() as u64);
    put_u64(&mut b, 88, m.qbytes);
    put_i32(&mut b, 96, guest_pid(m.lspid));
    put_i32(&mut b, 100, guest_pid(m.lrpid));
    b
}

/// A host pid as the guest's pid namespace numbers it.
pub fn guest_pid(host: i32) -> i32 {
    if host == 0 { 0 } else { crate::pidns::guest_ret(host as i64) as i32 }
}

/// This process's shared memory attachments: address, segment id, size.
pub(crate) static ATTACHED: Mutex<BTreeMap<u64, (i32, u64)>> = Mutex::new(BTreeMap::new());

pub fn attached(addr: u64) -> Option<(i32, u64)> {
    ATTACHED.lock().unwrap_or_else(|e| e.into_inner()).get(&addr).copied()
}

pub fn note_attached(addr: u64, id: i32, size: u64) {
    ATTACHED.lock().unwrap_or_else(|e| e.into_inner()).insert(addr, (id, size));
}

pub fn note_detached(addr: u64) {
    ATTACHED.lock().unwrap_or_else(|e| e.into_inner()).remove(&addr);
}

/// Count `n` more attachments of segment `id` for process `p` (`n` may be
/// negative).
pub fn attach_count(t: &mut Ipc, id: i32, p: Proc, n: i64) {
    if let Some(Obj { body: Body::Shm(s), .. }) = t.objs.get_mut(&(Kind::Shm as u8, id)) {
        match s.attached.iter_mut().find(|(q, _)| *q == p) {
            Some(a) => a.1 = (a.1 as i64 + n).max(0) as u32,
            None if n > 0 => s.attached.push((p, n as u32)),
            None => {}
        }
        s.attached.retain(|&(_, c)| c > 0);
    }
}

/// A fork child: the segments its parent had attached are its too (Linux
/// counts them for it).
pub fn forked_child() {
    let attached: Vec<i32> =
        ATTACHED.lock().unwrap_or_else(|e| e.into_inner()).values().map(|&(id, _)| id).collect();
    if attached.is_empty() {
        return;
    }
    let Some(r) = current() else { return };
    let me = me();
    let _ = r.update(|t| {
        for &id in &attached {
            attach_count(t, id, me, 1);
        }
        Ok(())
    });
}

/// This process runs another program (`exec` true) or ends: its
/// attachments go, and its undo adjustments are applied, as Linux does.
pub fn process_leaving(exec: bool) {
    let attached: Vec<(u64, (i32, u64))> =
        std::mem::take(&mut *ATTACHED.lock().unwrap_or_else(|e| e.into_inner()))
            .into_iter()
            .collect();
    if attached.is_empty() && !USED.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    let Some(r) = current() else { return };
    let me = me();
    let _ = r.update(|t| {
        for &(_, (id, _)) in &attached {
            attach_count(t, id, me, -1);
            if let Some(Obj { body: Body::Shm(s), .. }) = t.objs.get_mut(&(Kind::Shm as u8, id)) {
                s.dtime = now();
                s.lpid = me.0;
            }
        }
        if !exec {
            t.objs.each_mut(|_, o| {
                if let Body::Sem(s) = &mut o.body
                    && let Some(i) = s.undo.iter().position(|(p, _)| *p == me)
                {
                    let (_, adj) = s.undo.remove(i);
                    apply_undo(s, &adj);
                    return true;
                }
                false
            });
        }
        t.reap(&r);
        Ok(())
    });
}

/// `/proc/sysvipc/shm`, `sem` or `msg` of namespace record `r`.
pub fn proc_listing(r: &Record<Ipc>, kind: Kind) -> Vec<u8> {
    let t = r.get();
    let mut out = String::new();
    match kind {
        Kind::Shm => out.push_str(
            "       key      shmid perms                  size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime                   rss                  swap\n",
        ),
        Kind::Sem => out.push_str("       key      semid perms      nsems   uid   gid  cuid  cgid      otime      ctime\n"),
        Kind::Msg => out.push_str(
            "       key      msqid perms      cbytes       qnum lspid lrpid   uid   gid  cuid  cgid      stime      rtime      ctime\n",
        ),
    }
    for (&(_, id), o) in t.objs.iter().filter(|(_, o)| o.kind() == kind) {
        let p = &o.perm;
        match &o.body {
            Body::Shm(s) => out.push_str(&format!(
                "{:10} {:10}  {:4o} {:21} {:5} {:5} {:5} {:5} {:5} {:5} {:5} {:10} {:10} {:10} {:21} {:21}\n",
                o.key,
                id,
                p.mode & 0o777,
                s.size,
                guest_pid(s.cpid),
                guest_pid(s.lpid),
                s.attached.iter().map(|&(_, n)| n as u64).sum::<u64>(),
                p.uid,
                p.gid,
                p.cuid,
                p.cgid,
                s.atime,
                s.dtime,
                o.ctime,
                0,
                0
            )),
            Body::Sem(s) => out.push_str(&format!(
                "{:10} {:10}  {:4o} {:10} {:5} {:5} {:5} {:5} {:10} {:10}\n",
                o.key,
                id,
                p.mode & 0o777,
                s.vals.len(),
                p.uid,
                p.gid,
                p.cuid,
                p.cgid,
                s.otime,
                o.ctime
            )),
            Body::Msg(m) => out.push_str(&format!(
                "{:10} {:10}  {:4o}  {:10} {:10} {:5} {:5} {:5} {:5} {:5} {:5} {:10} {:10} {:10}\n",
                o.key,
                id,
                p.mode & 0o777,
                m.msgs.iter().map(|(_, t)| t.len()).sum::<usize>(),
                m.msgs.len(),
                guest_pid(m.lspid),
                guest_pid(m.lrpid),
                p.uid,
                p.gid,
                p.cuid,
                p.cgid,
                m.stime,
                m.rtime,
                o.ctime
            )),
        }
    }
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Changes reach another process's copy through the journal, and the
    /// data written whole when the journal outgrows it, in order.
    #[test]
    fn changes_reach_another_process() {
        use std::os::unix::ffi::OsStrExt;
        let dir = std::env::temp_dir().join(format!("fwe-ipc-journal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let d = dir.as_os_str().as_bytes().to_vec();
        // Two processes' views of one namespace.
        let a = Record::<Ipc>::at(d.clone(), Ipc::default).unwrap();
        let b = Record::<Ipc>::at(d.clone(), Ipc::default).unwrap();
        let mut live: Vec<(i32, i32)> = Vec::new();
        for key in 0..3000 {
            let r = if key % 3 == 0 { &a } else { &b };
            let sem = Sem { vals: vec![(key, 0)], ..Sem::default() };
            let id = r.update(|t| t.create(Kind::Sem, key, Perm::default(), Body::Sem(sem), 32000));
            live.push((id.unwrap(), key));
            if key % 5 == 0 {
                let (gone, _) = live.remove(0);
                let other = if key % 2 == 0 { &a } else { &b };
                other
                    .update(|t| t.objs.remove(&(Kind::Sem as u8, gone)).map(|_| ()).ok_or(0))
                    .unwrap();
            }
        }
        // A third process, which reads it from the start.
        let c = Record::<Ipc>::join(&d, 0).unwrap();
        for r in [&a, &b, &c] {
            let t = r.get();
            assert_eq!(t.count(Kind::Sem), live.len());
            for &(id, key) in &live {
                let o = &t.objs[&(Kind::Sem as u8, id)];
                assert_eq!(o.key, key);
                let Body::Sem(s) = &o.body else { panic!() };
                assert_eq!(s.vals, vec![(key, 0)]);
            }
        }
        // The journal never outgrows the data by much.
        let size = |n: &str| std::fs::metadata(dir.join(n)).map_or(0, |m| m.len());
        assert!(size("journal") <= size("data").max(64 << 10));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn objects_survive_their_encoding() {
        let mut t = Ipc::default();
        let perm = Perm { uid: 1, gid: 2, cuid: 1, cgid: 2, mode: 0o640 };
        let shm = t
            .create(Kind::Shm, 7, perm, Body::Shm(Shm { size: 4096, ..Shm::default() }), 10)
            .unwrap();
        let sem = Sem {
            vals: vec![(3, 9), (0, 0)],
            undo: vec![((5, 6), vec![(1, -2)])],
            ..Sem::default()
        };
        let sem = t.create(Kind::Sem, 7, perm, Body::Sem(sem), 10).unwrap();
        let mut msg = Msg { qbytes: MSGMNB, ..Msg::default() };
        msg.msgs.push_back((4, b"hi".to_vec()));
        let msg = t.create(Kind::Msg, 8, perm, Body::Msg(msg), 10).unwrap();
        // Ids are per kind: the same first id, told apart by kind.
        assert_eq!((shm, sem, msg), (0, 0, 0));
        let mut e = Enc::new();
        t.encode(&mut e);
        let bytes = e.into_bytes();
        let back = Ipc::decode(&mut Dec::new(&bytes));
        assert_eq!(back.objs.len(), 3);
        let Body::Sem(s) = &back.objs[&(Kind::Sem as u8, sem)].body else { panic!() };
        assert_eq!(s.vals, vec![(3, 9), (0, 0)]);
        assert_eq!(s.undo, vec![((5, 6), vec![(1, -2)])]);
        let Body::Msg(m) = &back.objs[&(Kind::Msg as u8, msg)].body else { panic!() };
        assert_eq!(m.msgs, [(4, b"hi".to_vec())]);
        // The next of a kind takes the next slot; a freed one is reused
        // under a new sequence.
        let shm2 = t.create(Kind::Shm, 9, perm, Body::Shm(Shm::default()), 10).unwrap();
        assert_eq!(shm2, 1);
        t.objs.remove(&(Kind::Shm as u8, shm));
        let shm3 = t.create(Kind::Shm, 10, perm, Body::Shm(Shm::default()), 10).unwrap();
        assert_eq!(shm3, IPCMNI);
        assert_eq!(t.by_key(Kind::Shm, 10), Some(shm3));
    }
}
