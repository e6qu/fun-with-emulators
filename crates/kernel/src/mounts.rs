//! Mount tables: what each mount namespace has mounted where.
//!
//! A mount attaches a filesystem at a path in its parent mount, as on
//! Linux: resolution starts at the namespace's root mount and, at each
//! directory it enters, looks for a mount attached there to its current
//! mount (mounts stacked at one path attach to each other, the topmost
//! last). A mount's path ([`Mount::point`]) is absolute in the namespace's
//! view; a process's root is a path in that view too
//! ([`crate::fs::Fs`]).
//!
//! A filesystem is a host directory (the rootfs, a bind mount's source, a
//! tmpfs's backing directory, all [`Source::Host`]), a stack of them
//! ([`Source::Overlay`], see [`crate::overlay`]) or one fwe generates
//! (`proc`, `sysfs`, `cgroup2`, `devpts`, `mqueue`), each reached from
//! [`Mount::root`], the path inside it the mount shows (a bind mount of a
//! subdirectory).
//!
//! The table is the namespace's, shared by every process in it, so it lives
//! in the host filesystem ([`store`]): each process keeps a copy and
//! rereads it when another has changed it.

use fwe_abi::errno;

/// Mount flags (`MS_*`) a mount carries.
pub mod ms {
    pub const RDONLY: u64 = 1;
    pub const NOSUID: u64 = 2;
    pub const NODEV: u64 = 4;
    pub const NOEXEC: u64 = 8;
    pub const SYNCHRONOUS: u64 = 16;
    pub const REMOUNT: u64 = 32;
    pub const MANDLOCK: u64 = 64;
    pub const DIRSYNC: u64 = 128;
    pub const NOSYMFOLLOW: u64 = 256;
    pub const NOATIME: u64 = 1024;
    pub const NODIRATIME: u64 = 2048;
    pub const BIND: u64 = 4096;
    pub const MOVE: u64 = 8192;
    pub const REC: u64 = 16384;
    pub const SILENT: u64 = 32768;
    pub const POSIXACL: u64 = 1 << 16;
    pub const UNBINDABLE: u64 = 1 << 17;
    pub const PRIVATE: u64 = 1 << 18;
    pub const SLAVE: u64 = 1 << 19;
    pub const SHARED: u64 = 1 << 20;
    pub const RELATIME: u64 = 1 << 21;
    pub const KERNMOUNT: u64 = 1 << 22;
    pub const I_VERSION: u64 = 1 << 23;
    pub const STRICTATIME: u64 = 1 << 24;
    pub const LAZYTIME: u64 = 1 << 25;
    /// The flags a mount keeps (the rest say what `mount` is to do).
    pub const PER_MOUNT: u64 = RDONLY
        | NOSUID
        | NODEV
        | NOEXEC
        | NOSYMFOLLOW
        | NOATIME
        | NODIRATIME
        | RELATIME
        | STRICTATIME;
    /// The propagation types.
    pub const PROPAGATION: u64 = UNBINDABLE | PRIVATE | SLAVE | SHARED;
}

/// Filesystem types and their `statfs` magic numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FsType {
    /// The rootfs and what is bound from it: a disk filesystem, reported
    /// as ext4.
    Ext4,
    Tmpfs,
    Proc,
    Sysfs,
    Cgroup2,
    Devpts,
    Mqueue,
    Overlay,
    /// A namespace's file bound to a path ([`Source::Ns`]).
    Nsfs,
}

impl FsType {
    pub fn name(self) -> &'static str {
        match self {
            FsType::Ext4 => "ext4",
            FsType::Tmpfs => "tmpfs",
            FsType::Proc => "proc",
            FsType::Sysfs => "sysfs",
            FsType::Cgroup2 => "cgroup2",
            FsType::Devpts => "devpts",
            FsType::Mqueue => "mqueue",
            FsType::Overlay => "overlay",
            FsType::Nsfs => "nsfs",
        }
    }

    /// `f_type` in `statfs`.
    pub fn magic(self) -> i64 {
        match self {
            FsType::Ext4 => 0xEF53,
            FsType::Tmpfs => 0x0102_1994,
            FsType::Proc => 0x9fa0,
            FsType::Sysfs => 0x6265_6572,
            FsType::Cgroup2 => 0x6367_7270,
            FsType::Devpts => 0x1cd1,
            FsType::Mqueue => 0x1980_2002,
            FsType::Overlay => crate::overlay::MAGIC,
            FsType::Nsfs => 0x6e73_6673,
        }
    }

    /// The type `mount(2)` names, for the ones fwe can mount.
    pub fn from_name(name: &[u8]) -> Option<FsType> {
        Some(match name {
            b"tmpfs" => FsType::Tmpfs,
            b"proc" => FsType::Proc,
            b"sysfs" => FsType::Sysfs,
            b"cgroup2" => FsType::Cgroup2,
            b"devpts" => FsType::Devpts,
            b"mqueue" => FsType::Mqueue,
            b"overlay" => FsType::Overlay,
            _ => return None,
        })
    }

    fn code(self) -> u32 {
        self as u32
    }

    pub(crate) fn from_code(c: u32) -> FsType {
        match c {
            1 => FsType::Tmpfs,
            2 => FsType::Proc,
            3 => FsType::Sysfs,
            4 => FsType::Cgroup2,
            5 => FsType::Devpts,
            6 => FsType::Mqueue,
            7 => FsType::Overlay,
            8 => FsType::Nsfs,
            _ => FsType::Ext4,
        }
    }
}

/// Where a mount's files come from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// A host directory, or a host file for a file bind mount: the path
    /// the mount's [`Mount::root`] is taken in.
    Host(Vec<u8>),
    /// Host directories stacked as one ([`crate::overlay`]).
    Overlay(std::sync::Arc<crate::overlay::Layers>),
    /// A filesystem fwe generates.
    Synthetic,
    /// A namespace, its file bound to the mount point: what opening it
    /// gives, and what it keeps from being freed.
    Ns(crate::nsfd::NsRef),
}

/// One mount.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mount {
    /// Unique in the table; what `/proc/self/mountinfo` shows.
    pub id: u32,
    /// The mount this one is attached to; the root mount's is its own id.
    pub parent: u32,
    /// Where it is attached: an absolute path in the namespace's view.
    pub point: Vec<u8>,
    pub fstype: FsType,
    pub source: Source,
    /// The path inside the filesystem the mount shows (`/` for a whole
    /// filesystem; a subdirectory, or a file, for a bind mount).
    pub root: Vec<u8>,
    /// Per-mount `MS_*` flags ([`ms::PER_MOUNT`]).
    pub flags: u64,
    /// Propagation: `MS_SHARED` (with [`Mount::peer`]), `MS_SLAVE` (with
    /// [`Mount::master`]), both, `MS_UNBINDABLE`, or `MS_PRIVATE`; what is
    /// mounted under a shared mount propagates ([`Table::propagate`]).
    pub propagation: u64,
    /// The peer group a shared mount is in (0: none).
    pub peer: u32,
    /// The peer group a slave mount receives from (0: none).
    pub master: u32,
    /// The source as `mount` was given it, for `mountinfo`.
    pub device: Vec<u8>,
    /// The filesystem's options (`mode=755` and the like).
    pub options: Vec<u8>,
}

/// What unique mount ids (`STATX_MNT_ID_UNIQUE`, `statmount`) count up
/// from: Linux's `MNT_UNIQUE_ID_OFFSET`, above any old 32-bit id.
pub const UNIQUE_ID_BASE: u64 = 1 << 31;

impl Mount {
    /// The mount's unique id: its id above [`UNIQUE_ID_BASE`] (a table
    /// never reuses an id).
    pub fn unique_id(&self) -> u64 {
        UNIQUE_ID_BASE + u64::from(self.id)
    }

    /// The host path of `rest` (a path inside the mount, starting with
    /// `/` or empty), for a host-backed mount.
    pub fn host_path(&self, rest: &[u8]) -> Option<Vec<u8>> {
        let Source::Host(base) = &self.source else { return None };
        Some(join(&join(base, &self.root), rest))
    }

    /// The path inside the filesystem `rest` names.
    pub fn fs_path(&self, rest: &[u8]) -> Vec<u8> {
        join(&self.root, rest)
    }

    /// The per-mount options `mountinfo` and `mounts` show: `ro` or `rw`,
    /// then the flags set.
    pub fn mount_options(&self) -> Vec<u8> {
        let mut opts = if self.read_only() { b"ro".to_vec() } else { b"rw".to_vec() };
        for (flag, name) in [
            (ms::NOSUID, &b"nosuid"[..]),
            (ms::NODEV, b"nodev"),
            (ms::NOEXEC, b"noexec"),
            (ms::NOATIME, b"noatime"),
            (ms::NODIRATIME, b"nodiratime"),
            (ms::RELATIME, b"relatime"),
            (ms::NOSYMFOLLOW, b"nosymfollow"),
        ] {
            if self.flags & flag != 0 {
                opts.push(b',');
                opts.extend_from_slice(name);
            }
        }
        opts
    }

    pub fn read_only(&self) -> bool {
        self.flags & ms::RDONLY != 0
    }
}

/// `a` and `b` joined with one `/` between them; `b` may be empty or start
/// with `/`.
pub fn join(a: &[u8], b: &[u8]) -> Vec<u8> {
    let b = b.strip_prefix(b"/").unwrap_or(b);
    if b.is_empty() {
        return if a.is_empty() { b"/".to_vec() } else { a.to_vec() };
    }
    let mut out = a.to_vec();
    if out.last() != Some(&b'/') {
        out.push(b'/');
    }
    out.extend_from_slice(b);
    out
}

/// The part of the normalized absolute path `path` under `prefix`, with
/// its leading `/` (empty when `path` is `prefix`), if `path` is there.
pub fn under<'a>(path: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if prefix == b"/" {
        return Some(if path == b"/" { b"" } else { path });
    }
    let rest = path.strip_prefix(prefix)?;
    (rest.is_empty() || rest.first() == Some(&b'/')).then_some(rest)
}

/// A namespace's mounts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Table {
    pub mounts: Vec<Mount>,
    /// The id the next mount gets.
    pub next_id: u32,
    /// The id the next peer group gets, when the shared count of them
    /// cannot be had ([`store::next_group`]).
    pub next_group: u32,
    /// What this change propagates to other namespaces, carried out once
    /// it is made ([`store::Ns::update`]); never kept in the record.
    pub outbox: Vec<Propagation>,
    /// The mounts `umount2(MNT_EXPIRE)` marked, not used since: the next
    /// such call unmounts them.
    pub expiring: Vec<u32>,
    /// The directory of the user namespace that owns it (empty for the
    /// initial one).
    pub owner: Vec<u8>,
}

/// The propagation flags of a mount in peer group `peer` (0: none) and a
/// slave of group `master` (0: none).
fn shared_flags(peer: u32, master: u32) -> u64 {
    match (peer != 0, master != 0) {
        (true, true) => ms::SHARED | ms::SLAVE,
        (true, false) => ms::SHARED,
        (false, true) => ms::SLAVE,
        (false, false) => ms::PRIVATE,
    }
}

/// A change of a namespace's mounts that reaches the mounts of other
/// namespaces in its peer group (or slaves of it), as propagation does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Propagation {
    /// `tree` (its root first, points relative to it) was mounted at `at`,
    /// a path in filesystem `source`, under a mount of peer group `group`,
    /// whose slaves are those of `group` and of the groups `slaves`; the
    /// copies made in a member of each of those groups are shared in the
    /// groups `made` has for it, one for each mount of the tree.
    Attach {
        group: u32,
        slaves: Vec<u32>,
        made: Vec<(u32, Vec<u32>)>,
        source: Source,
        at: Vec<u8>,
        tree: Vec<Mount>,
    },
    /// The tree of mounts at `tree` (places relative to its root) mounted
    /// at `at` in `source`, under a mount of `group`, was unmounted.
    Detach { group: u32, slaves: Vec<u32>, source: Source, at: Vec<u8>, tree: Vec<Vec<u8>> },
    /// No mount is in group `from` any longer: its slaves are slaves of
    /// group `to` (or, if 0, of none).
    Regroup { from: u32, to: u32 },
}

impl Table {
    /// The table a namespace starts with when nothing was mounted in it:
    /// the rootfs at `root_host` and what Linux always has mounted.
    pub fn initial(root_host: &[u8], shm_host: Option<&[u8]>, cgroup_host: Option<&[u8]>) -> Table {
        let mut t = Table {
            mounts: Vec::new(),
            next_id: 1,
            next_group: 1,
            outbox: Vec::new(),
            expiring: Vec::new(),
            owner: Vec::new(),
        };
        let root = t.alloc();
        t.mounts.push(Mount {
            id: root,
            parent: root,
            point: b"/".to_vec(),
            fstype: FsType::Ext4,
            source: Source::Host(root_host.to_vec()),
            root: b"/".to_vec(),
            flags: ms::RELATIME,
            propagation: ms::PRIVATE,
            peer: 0,
            master: 0,
            device: b"/dev/root".to_vec(),
            options: b"rw".to_vec(),
        });
        let add = |t: &mut Table, parent: u32, point: &[u8], fstype: FsType, opts: &[u8]| {
            let id = t.alloc();
            t.mounts.push(Mount {
                id,
                parent,
                point: point.to_vec(),
                fstype,
                source: Source::Synthetic,
                root: b"/".to_vec(),
                flags: ms::NOSUID | ms::NODEV | ms::NOEXEC | ms::RELATIME,
                propagation: ms::PRIVATE,
                peer: 0,
                master: 0,
                device: fstype.name().as_bytes().to_vec(),
                options: opts.to_vec(),
            });
            id
        };
        add(&mut t, root, b"/proc", FsType::Proc, b"rw");
        let sys = add(&mut t, root, b"/sys", FsType::Sysfs, b"rw");
        if let Some(cg) = cgroup_host {
            let id = t.alloc();
            t.mounts.push(Mount {
                id,
                parent: sys,
                point: b"/sys/fs/cgroup".to_vec(),
                fstype: FsType::Cgroup2,
                source: Source::Host(cg.to_vec()),
                root: b"/".to_vec(),
                flags: ms::NOSUID | ms::NODEV | ms::NOEXEC | ms::RELATIME,
                propagation: ms::PRIVATE,
                peer: 0,
                master: 0,
                device: b"cgroup2".to_vec(),
                options: b"rw,nsdelegate".to_vec(),
            });
        }
        add(&mut t, root, b"/dev/pts", FsType::Devpts, b"rw,gid=5,mode=620,ptmxmode=000");
        add(&mut t, root, b"/dev/mqueue", FsType::Mqueue, b"rw");
        if let Some(shm) = shm_host {
            let id = t.alloc();
            t.mounts.push(Mount {
                id,
                parent: root,
                point: b"/dev/shm".to_vec(),
                fstype: FsType::Tmpfs,
                source: Source::Host(shm.to_vec()),
                root: b"/".to_vec(),
                flags: ms::NOSUID | ms::NODEV,
                propagation: ms::PRIVATE,
                peer: 0,
                master: 0,
                device: b"tmpfs".to_vec(),
                options: b"rw".to_vec(),
            });
        }
        t
    }

    fn alloc(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    pub fn get(&self, id: u32) -> Option<&Mount> {
        self.mounts.iter().find(|m| m.id == id)
    }

    /// The namespace's root mount: the bottom one at `/` and what is
    /// stacked on it, topmost.
    pub fn root(&self) -> &Mount {
        let bottom = self.mounts.iter().find(|m| m.parent == m.id).expect("a root mount");
        self.topmost(bottom.id, b"/").unwrap_or(bottom)
    }

    /// The mount attached at `point` to mount `parent`, with what is stacked
    /// on it: the one resolution enters there.
    pub fn child_at(&self, parent: u32, point: &[u8]) -> Option<&Mount> {
        let first = self
            .mounts
            .iter()
            .rfind(|m| m.parent == parent && m.id != m.parent && m.point == point)?;
        Some(self.topmost(first.id, point).unwrap_or(first))
    }

    /// The top of the stack of mounts at `point` above mount `id`.
    fn topmost(&self, id: u32, point: &[u8]) -> Option<&Mount> {
        let mut top: Option<&Mount> = None;
        let mut at = id;
        while let Some(m) =
            self.mounts.iter().rfind(|m| m.parent == at && m.id != m.parent && m.point == point)
        {
            top = Some(m);
            at = m.id;
        }
        top
    }

    /// The mount `path` (a normalized absolute path in the namespace's
    /// view) is in, and the rest of `path` inside it: the mounts entered by
    /// walking it from the root.
    pub fn locate<'a>(&'a self, path: &[u8]) -> (&'a Mount, Vec<u8>) {
        let mut m = self.root();
        let mut at = b"/".to_vec();
        for comp in path.split(|&b| b == b'/').filter(|c| !c.is_empty()) {
            at = join(&at, comp);
            if let Some(child) = self.child_at(m.id, &at) {
                m = child;
            }
        }
        let rest = under(path, &m.point).unwrap_or(b"").to_vec();
        (m, rest)
    }

    /// Every mount under mount `id`, its descendants first.
    fn descendants(&self, id: u32) -> Vec<u32> {
        let mut out = Vec::new();
        let mut frontier = vec![id];
        while let Some(p) = frontier.pop() {
            for m in self.mounts.iter().filter(|m| m.parent == p && m.id != m.parent) {
                out.push(m.id);
                frontier.push(m.id);
            }
        }
        out.reverse();
        out
    }

    /// Attach a new mount at `point`, onto whatever `point` resolves to,
    /// and propagate it ([`Table::propagate`]).
    #[allow(clippy::too_many_arguments)]
    pub fn mount(
        &mut self,
        point: &[u8],
        fstype: FsType,
        source: Source,
        root: Vec<u8>,
        flags: u64,
        device: Vec<u8>,
        options: Vec<u8>,
    ) -> u32 {
        let id = self.mount_one(point, fstype, source, root, flags, device, options);
        self.propagate(id);
        id
    }

    /// [`Table::mount`] without propagating.
    #[allow(clippy::too_many_arguments)]
    fn mount_one(
        &mut self,
        point: &[u8],
        fstype: FsType,
        source: Source,
        root: Vec<u8>,
        flags: u64,
        device: Vec<u8>,
        options: Vec<u8>,
    ) -> u32 {
        // Onto the mount `point` is in; onto the one whose root it is, for a
        // mount stacked over another.
        let parent = self.locate(point).0.id;
        // A new mount under a shared one is shared, in a peer group of its
        // own; else private.
        let shared = self.get(parent).is_some_and(|p| p.peer != 0);
        let (propagation, peer) =
            if shared { (ms::SHARED, self.alloc_group()) } else { (ms::PRIVATE, 0) };
        let id = self.alloc();
        self.mounts.push(Mount {
            id,
            parent,
            point: point.to_vec(),
            fstype,
            source,
            root,
            flags: flags & ms::PER_MOUNT,
            propagation,
            peer,
            master: 0,
            device,
            options,
        });
        id
    }

    /// A new peer group's id: unique across namespaces, whose mounts can be
    /// peers.
    fn alloc_group(&mut self) -> u32 {
        store::next_group().unwrap_or_else(|| {
            let g = self.next_group;
            self.next_group += 1;
            g
        })
    }

    fn get_mut(&mut self, id: u32) -> Option<&mut Mount> {
        self.mounts.iter_mut().find(|m| m.id == id)
    }

    /// Mount `id`, a copy of `src`, joins its propagation as a clone does
    /// on Linux: a peer of a shared one, a slave of a slave's master.
    fn clone_propagation(&mut self, id: u32, src: &Mount) {
        let Some(m) = self.get_mut(id) else { return };
        if src.peer == 0 && src.master == 0 {
            return;
        }
        m.peer = src.peer;
        m.master = src.master;
        m.propagation = src.propagation & (ms::SHARED | ms::SLAVE);
    }

    /// A bind mount of `from` (a path in the namespace's view) at `to`;
    /// with `recursive`, the mounts under `from` come along.
    pub fn bind(
        &mut self,
        from: &[u8],
        to: &[u8],
        recursive: bool,
        flags: u64,
    ) -> Result<u32, i32> {
        let (src, rest) = self.locate(from);
        let src = src.clone();
        if src.propagation & ms::UNBINDABLE != 0 {
            return Err(errno::EINVAL);
        }
        let id = self.mount_one(
            to,
            src.fstype,
            src.source.clone(),
            src.fs_path(&rest),
            (src.flags & !ms::RDONLY) | (flags & ms::RDONLY),
            src.device.clone(),
            src.options.clone(),
        );
        self.clone_propagation(id, &src);
        if recursive {
            // Each mount under `from`, attached to its copy's parent at the
            // matching path under `to`.
            let mut copies = vec![(src.id, id)];
            let below: Vec<Mount> = self
                .mounts
                .iter()
                .filter(|m| m.id != id && under(&m.point, from).is_some_and(|r| !r.is_empty()))
                .filter(|m| self.is_below(m.id, src.id))
                .cloned()
                .collect();
            for m in parent_first(src.id, below) {
                let Some(&(_, parent)) = copies.iter().find(|(o, _)| *o == m.parent) else {
                    continue;
                };
                let point = join(to, under(&m.point, from).unwrap_or(b""));
                let copy = self.alloc();
                self.mounts.push(Mount { id: copy, parent, point, ..m.clone() });
                copies.push((m.id, copy));
            }
        }
        self.propagate(id);
        Ok(id)
    }

    /// The mount with unique id `id`.
    pub fn by_unique(&self, id: u64) -> Option<&Mount> {
        self.mounts.iter().find(|m| m.unique_id() == id)
    }

    /// A copy of the mount `from` (a path in the namespace's view) is in,
    /// showing what is at `from`, and with `recursive` of the mounts under
    /// it: a detached tree ([`Table::attach_tree`]). Its first mount is
    /// the root (`point` empty); the others' points are relative to it and
    /// their parents are the copied mounts' ids.
    pub fn copy_tree(&self, from: &[u8], recursive: bool) -> Result<Vec<Mount>, i32> {
        let (src, rest) = self.locate(from);
        if src.propagation & ms::UNBINDABLE != 0 {
            return Err(errno::EINVAL);
        }
        let mut tree = vec![Mount { point: Vec::new(), root: src.fs_path(&rest), ..src.clone() }];
        if recursive {
            let below: Vec<Mount> = self
                .mounts
                .iter()
                .filter(|m| under(&m.point, from).is_some_and(|r| !r.is_empty()))
                .filter(|m| self.is_below(m.id, src.id))
                .cloned()
                .collect();
            for m in parent_first(src.id, below) {
                let point = under(&m.point, from).unwrap_or(b"").to_vec();
                tree.push(Mount { point, ..m });
            }
        }
        Ok(tree)
    }

    /// Attach detached `tree` ([`Table::copy_tree`], or a new filesystem's
    /// one mount) at `to`, or with `beneath` under the mount at `to`
    /// (which must be a mount's root, not the namespace's), between it and
    /// what it is attached to. Returns the root's new id.
    pub fn attach_tree(&mut self, tree: &[Mount], to: &[u8], beneath: bool) -> Result<u32, i32> {
        let Some(top) = tree.first() else { return Err(errno::EINVAL) };
        let (at, rest) = self.locate(to);
        let (parent, above) = if beneath {
            if !rest.is_empty() || at.parent == at.id {
                return Err(errno::EINVAL);
            }
            (at.parent, Some(at.id))
        } else {
            (at.id, None)
        };
        let shared_parent = self.get(parent).is_some_and(|p| p.peer != 0);
        let root = self.alloc();
        let mut copies = vec![(top.id, root)];
        let mut m = Mount { id: root, parent, point: to.to_vec(), ..top.clone() };
        if m.peer == 0 && shared_parent {
            // Under a shared mount: shared, in a group of its own.
            m.peer = self.alloc_group();
            m.propagation = (m.propagation & ms::SLAVE) | ms::SHARED;
        }
        self.mounts.push(m);
        if let Some(above) = above
            && let Some(a) = self.get_mut(above)
        {
            a.parent = root;
        }
        for m in &tree[1..] {
            let Some(&(_, parent)) = copies.iter().find(|(o, _)| *o == m.parent) else {
                continue;
            };
            let id = self.alloc();
            let point = join(to, &m.point);
            self.mounts.push(Mount { id, parent, point, ..m.clone() });
            copies.push((m.id, id));
        }
        self.propagate(root);
        Ok(root)
    }

    /// Whether mount `id` is below mount `ancestor`.
    pub fn is_below(&self, mut id: u32, ancestor: u32) -> bool {
        while let Some(m) = self.get(id) {
            if m.parent == ancestor {
                return true;
            }
            if m.parent == m.id {
                return false;
            }
            id = m.parent;
        }
        false
    }

    /// Detach the mount whose root `path` is, with everything mounted under
    /// it. `EINVAL` if `path` is not a mount's root. What it propagated to
    /// goes with it ([`Table::drop_copy`]).
    pub fn umount(&mut self, path: &[u8]) -> Result<(), i32> {
        let (m, rest) = self.locate(path);
        if !rest.is_empty() || m.parent == m.id {
            return Err(errno::EINVAL);
        }
        let m = m.clone();
        let mut gone = self.descendants(m.id);
        gone.push(m.id);
        // The tree's mounts, by their places relative to its root.
        let tree: Vec<Vec<u8>> = gone
            .iter()
            .filter_map(|g| self.get(*g))
            .map(|d| under(&d.point, &m.point).unwrap_or(b"").to_vec())
            .collect();
        let Some(p) = self.get(m.parent).cloned().filter(|p| p.peer != 0) else {
            self.mounts.retain(|o| !gone.contains(&o.id));
            return Ok(());
        };
        let slaves = self.slave_groups(p.peer);
        if let Some(at) = under(&m.point, &p.point).map(|r| join(&p.root, r)) {
            self.outbox.push(Propagation::Detach {
                group: p.peer,
                slaves: slaves.clone(),
                source: p.source.clone(),
                at,
                tree: tree.clone(),
            });
        }
        for (t, _) in self.targets(p.peer, &slaves, Some(p.id)) {
            let Some(at) = self.counterpart(p.id, &m.point, t) else { continue };
            let copy = self
                .mounts
                .iter()
                .find(|c| c.parent == t && c.id != t && c.point == at && !gone.contains(&c.id))
                .map(|c| c.id);
            if let Some(c) = copy {
                gone.extend(self.drop_copy(c, &tree));
            }
        }
        self.mounts.retain(|o| !gone.contains(&o.id));
        Ok(())
    }

    /// The copy `c` of an unmounted tree (its mounts' places relative to
    /// its root in `tree`) goes with it, as Linux's `propagate_umount`
    /// has it: with what is under it, if all that is copies of the tree
    /// too; else (something else is mounted in it) it stays. A mount
    /// stacked on its root is not the tree's: it takes the copy's place.
    /// Returns the mounts to remove.
    fn drop_copy(&mut self, c: u32, tree: &[Vec<u8>]) -> Vec<u32> {
        let Some(cm) = self.get(c).cloned() else { return Vec::new() };
        let above = self.mounts.iter().find(|o| o.parent == c && o.id != c && o.point == cm.point);
        let above = above.map(|o| o.id);
        let kept: Vec<u32> = above.map_or_else(Vec::new, |a| {
            let mut k = self.descendants(a);
            k.push(a);
            k
        });
        let mut out: Vec<u32> =
            self.descendants(c).into_iter().filter(|d| !kept.contains(d)).collect();
        let foreign = out.iter().filter_map(|d| self.get(*d)).any(|d| {
            let rel = under(&d.point, &cm.point).unwrap_or(b"");
            rel.is_empty() || !tree.iter().any(|t| t == rel)
        });
        if foreign {
            return Vec::new();
        }
        if let Some(a) = above
            && let Some(o) = self.get_mut(a)
        {
            o.parent = cm.parent;
        }
        out.push(c);
        out
    }

    /// The peer groups whose members receive, as slaves, what reaches
    /// group `g`: its slaves' groups, theirs, and so on, across every
    /// mount namespace (a slave's group can have members in several).
    fn slave_groups(&self, g: u32) -> Vec<u32> {
        let others = store::others();
        let all: Vec<&Mount> =
            self.mounts.iter().chain(others.iter().flat_map(|t| t.mounts.iter())).collect();
        let mut groups = vec![g];
        loop {
            let found: Vec<u32> = all
                .iter()
                .filter(|m| m.peer != 0 && groups.contains(&m.master) && !groups.contains(&m.peer))
                .map(|m| m.peer)
                .collect();
            if found.is_empty() {
                break;
            }
            for f in found {
                if !groups.contains(&f) {
                    groups.push(f);
                }
            }
        }
        groups.remove(0);
        groups
    }

    /// The mounts here a change under a mount of group `g` reaches (but
    /// `skip`): its peers, as peers, and the slaves of `g` or of the groups
    /// `slaves`, as slaves.
    fn targets(&self, g: u32, slaves: &[u32], skip: Option<u32>) -> Vec<(u32, bool)> {
        self.mounts
            .iter()
            .filter(|m| Some(m.id) != skip)
            .filter_map(|m| {
                if m.peer == g {
                    Some((m.id, true))
                } else if m.master != 0 && (m.master == g || slaves.contains(&m.master)) {
                    Some((m.id, false))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Where in mount `t` the place `point` of mount `parent` is, if `t`
    /// shows it (it is of the same filesystem, below `t`'s root).
    fn counterpart(&self, parent: u32, point: &[u8], t: u32) -> Option<Vec<u8>> {
        let (p, t) = (self.get(parent)?, self.get(t)?);
        if p.source != t.source {
            return None;
        }
        let in_fs = join(&p.root, under(point, &p.point)?);
        Some(join(&t.point, under(&in_fs, &t.root)?))
    }

    /// Propagate new mount `id` (and what is mounted under it) from its
    /// parent, as Linux does. Under a shared mount the tree is shared,
    /// each mount of it without a group given one; then a copy goes to the
    /// same place in each receiver ([`Table::targets`]): in a peer, peers
    /// of the tree's mounts; in a slave, slaves of them, and shared among
    /// the copies made in one shared slave group's members, in a group of
    /// their own. A copy goes beneath a mount the receiver already has
    /// there. Other namespaces receive it once this change is made
    /// ([`Propagation`]).
    pub fn propagate(&mut self, id: u32) {
        let Some(m) = self.get(id).cloned() else { return };
        let Some(p) = self.get(m.parent).cloned().filter(|p| p.peer != 0) else { return };
        let under_id = self.descendants(id);
        for d in std::iter::once(id).chain(under_id.iter().copied()) {
            if self.get(d).is_some_and(|d| d.peer == 0) {
                let g = self.alloc_group();
                if let Some(d) = self.get_mut(d) {
                    d.peer = g;
                    d.propagation = shared_flags(g, d.master);
                }
            }
        }
        let Some(m) = self.get(id).cloned() else { return };
        let below: Vec<Mount> = under_id.iter().filter_map(|d| self.get(*d).cloned()).collect();
        let tree: Vec<Mount> = std::iter::once(m.clone()).chain(parent_first(id, below)).collect();
        let slaves = self.slave_groups(p.peer);
        // A group for each copy in each shared slave group.
        let made: Vec<(u32, Vec<u32>)> = slaves
            .iter()
            .map(|&s| (s, tree.iter().map(|_| self.alloc_group()).collect()))
            .collect();
        if let Some(at) = under(&m.point, &p.point).map(|r| join(&p.root, r)) {
            let tree = tree
                .iter()
                .map(|d| {
                    let point = under(&d.point, &m.point).unwrap_or(b"").to_vec();
                    Mount { point, ..d.clone() }
                })
                .collect();
            self.outbox.push(Propagation::Attach {
                group: p.peer,
                slaves: slaves.clone(),
                made: made.clone(),
                source: p.source.clone(),
                at,
                tree,
            });
        }
        // Not to itself (a bind of a shared mount is its peer already).
        let targets: Vec<(u32, bool)> = self
            .targets(p.peer, &slaves, Some(p.id))
            .into_iter()
            .filter(|(t, _)| *t != id && !under_id.contains(t))
            .collect();
        for (t, as_peer) in targets {
            let Some(at) = self.counterpart(m.parent, &m.point, t) else { continue };
            self.copy_to(&tree, t, as_peer, at, &made);
        }
    }

    /// Copy `tree` (its root first, attached at `tree[0].point`; each
    /// other one at its place below that) into receiver `t` at `at`, as a
    /// peer or a slave (shared in the group `made` has for `t`'s, if `t`
    /// is a shared slave).
    fn copy_to(
        &mut self,
        tree: &[Mount],
        t: u32,
        as_peer: bool,
        at: Vec<u8>,
        made: &[(u32, Vec<u32>)],
    ) {
        let Some(m) = tree.first() else { return };
        let receiver = self.get(t).map_or(0, |t| t.peer);
        let fresh = (!as_peer && receiver != 0)
            .then(|| made.iter().find(|(s, _)| *s == receiver).map(|(_, f)| f))
            .flatten();
        // Beneath what `t` has there already.
        let above =
            self.mounts.iter().find(|c| c.parent == t && c.id != t && c.point == at).map(|c| c.id);
        let mut copies: Vec<(u32, u32)> = Vec::new();
        for (i, d) in tree.iter().enumerate() {
            let parent = if i == 0 {
                t
            } else {
                let Some(&(_, parent)) = copies.iter().find(|(o, _)| *o == d.parent) else {
                    continue;
                };
                parent
            };
            let (peer, master) = if as_peer {
                (d.peer, d.master)
            } else {
                (
                    fresh.and_then(|f| f.get(i).copied()).unwrap_or(0),
                    if d.peer != 0 { d.peer } else { d.master },
                )
            };
            let point = join(&at, under(&d.point, &m.point).unwrap_or(b""));
            let copy = self.alloc();
            let propagation = shared_flags(peer, master);
            self.mounts.push(Mount {
                id: copy,
                parent,
                point,
                peer,
                master,
                propagation,
                ..d.clone()
            });
            copies.push((d.id, copy));
        }
        if let Some(a) = above
            && let Some(&(_, root)) = copies.first()
            && let Some(c) = self.get_mut(a)
        {
            c.parent = root;
        }
    }

    /// The slaves of group `from`, which no mount is in any longer, become
    /// slaves of group `to` (or, if 0, of none).
    fn regroup(&mut self, from: u32, to: u32) {
        for s in self.mounts.iter_mut().filter(|s| s.master == from) {
            s.master = to;
            if s.propagation & ms::UNBINDABLE == 0 {
                s.propagation = shared_flags(s.peer, to);
            }
        }
    }

    /// Receive propagation `ev` from another namespace: in the members of
    /// its group here and the slaves of it ([`Table::targets`]).
    pub fn receive(&mut self, ev: &Propagation) {
        let (Propagation::Attach { group, slaves, source, at, .. }
        | Propagation::Detach { group, slaves, source, at, .. }) = ev
        else {
            if let Propagation::Regroup { from, to } = ev {
                self.regroup(*from, *to);
            }
            return;
        };
        for (t, as_peer) in self.targets(*group, slaves, None) {
            let Some(tm) = self.get(t).cloned() else { continue };
            if &tm.source != source {
                continue;
            }
            let Some(rest) = under(at, &tm.root) else { continue };
            let point = join(&tm.point, rest);
            match ev {
                Propagation::Attach { tree, made, .. } => {
                    // The tree's points are relative to its root: placed
                    // where it lands here.
                    let placed: Vec<Mount> = tree
                        .iter()
                        .map(|d| Mount { point: join(&point, &d.point), ..d.clone() })
                        .collect();
                    self.copy_to(&placed, t, as_peer, point, made);
                }
                Propagation::Detach { tree, .. } => {
                    let copy = self
                        .mounts
                        .iter()
                        .find(|c| c.parent == t && c.id != t && c.point == point)
                        .map(|c| c.id);
                    if let Some(c) = copy {
                        let gone = self.drop_copy(c, tree);
                        self.mounts.retain(|o| !gone.contains(&o.id));
                    }
                }
                Propagation::Regroup { .. } => {}
            }
        }
    }

    /// Move the mount whose root is `from` to `to`.
    pub fn move_mount(&mut self, from: &[u8], to: &[u8]) -> Result<(), i32> {
        let (m, rest) = self.locate(from);
        if !rest.is_empty() || m.parent == m.id {
            return Err(errno::EINVAL);
        }
        // Not out of a shared mount, as Linux has it.
        if self.get(m.parent).is_some_and(|p| p.peer != 0) {
            return Err(errno::EINVAL);
        }
        let id = m.id;
        let old_point = m.point.clone();
        let (target, _) = self.locate(to);
        if target.id == id || self.is_below(target.id, id) {
            // Into itself.
            return Err(errno::ELOOP);
        }
        let target = target.id;
        let moved = self.descendants(id);
        for m in self.mounts.iter_mut() {
            if m.id == id {
                m.parent = target;
                m.point = to.to_vec();
            } else if moved.contains(&m.id) {
                m.point = join(to, under(&m.point, &old_point).unwrap_or(b""));
            }
        }
        self.propagate(id);
        Ok(())
    }

    /// Move the mount whose root is `from` beneath the mount whose root is
    /// `to`: between that one and what it is attached to, keeping its id.
    pub fn move_beneath(&mut self, from: &[u8], to: &[u8]) -> Result<(), i32> {
        let (m, rest) = self.locate(from);
        if !rest.is_empty() || m.parent == m.id {
            return Err(errno::EINVAL);
        }
        let (id, old_point) = (m.id, m.point.clone());
        let (top, rest) = self.locate(to);
        if !rest.is_empty() || top.parent == top.id {
            return Err(errno::EINVAL);
        }
        let (top, below) = (top.id, top.parent);
        if top == id || self.is_below(top, id) || self.is_below(id, top) {
            return Err(errno::EINVAL);
        }
        // What was stacked on it stays where it was, on what it was on.
        let parent = self.get(id).map_or(0, |m| m.parent);
        for o in self.mounts.iter_mut() {
            if o.parent == id && o.point == old_point {
                o.parent = parent;
            }
        }
        let moved = self.descendants(id);
        for o in self.mounts.iter_mut() {
            if o.id == id {
                o.parent = below;
                o.point = to.to_vec();
            } else if o.id == top {
                o.parent = id;
            } else if moved.contains(&o.id) {
                o.point = join(to, under(&o.point, &old_point).unwrap_or(b""));
            }
        }
        Ok(())
    }

    /// Change the per-mount flags of the mount whose root is `path`, and
    /// its filesystem's options if `data` is given. A remount of a
    /// filesystem acts on the one mount: what is mounted twice is two
    /// separate filesystems here. Flags that name no access-time mode keep
    /// the mount's.
    pub fn remount(&mut self, path: &[u8], flags: u64, data: Option<Vec<u8>>) -> Result<(), i32> {
        let (m, rest) = self.locate(path);
        if !rest.is_empty() {
            return Err(errno::EINVAL);
        }
        let id = m.id;
        let m = self.mounts.iter_mut().find(|m| m.id == id).unwrap();
        // Naming no access-time mode keeps the mount's.
        const ATIME: u64 = ms::NOATIME | ms::NODIRATIME | ms::RELATIME | ms::STRICTATIME;
        let atime = if flags & ATIME == 0 { m.flags & ATIME } else { flags & ATIME };
        m.flags = (flags & !ATIME | atime) & ms::PER_MOUNT;
        if let Some(d) = data {
            m.options = d;
        }
        Ok(())
    }

    /// Set the propagation of the mount whose root is `path`, and with
    /// `recursive` of every mount under it.
    pub fn set_propagation(&mut self, path: &[u8], how: u64, recursive: bool) -> Result<(), i32> {
        let (m, rest) = self.locate(path);
        if !rest.is_empty() {
            return Err(errno::EINVAL);
        }
        let id = m.id;
        let mut ids = vec![id];
        if recursive {
            ids.extend(self.descendants(id));
        }
        // The groups with members in other namespaces too.
        let elsewhere: Vec<u32> = store::others()
            .iter()
            .flat_map(|t| t.mounts.iter().map(|m| m.peer).filter(|&g| g != 0).collect::<Vec<_>>())
            .collect();
        for id in ids {
            self.change_propagation(id, how & ms::PROPAGATION, &elsewhere);
        }
        Ok(())
    }

    /// Make mount `id` shared, a slave, private or unbindable, as Linux
    /// changes one: a shared mount keeps its peer group (or gets one); one
    /// made a slave receives from the group it leaves, if others are in
    /// it (here or in the namespaces whose groups `elsewhere` lists), or
    /// keeps its master; private and unbindable ones leave both.
    fn change_propagation(&mut self, id: u32, how: u64, elsewhere: &[u32]) {
        let Some(m) = self.get(id).cloned() else { return };
        let others = m.peer != 0
            && (elsewhere.contains(&m.peer)
                || self.mounts.iter().any(|o| o.id != id && o.peer == m.peer));
        if m.peer != 0 && !others && how != ms::SHARED {
            // The last of its group leaves it: the group's slaves, here and
            // in other namespaces, receive from what it received from, or
            // from nothing.
            self.regroup(m.peer, m.master);
            self.outbox.push(Propagation::Regroup { from: m.peer, to: m.master });
        }
        let (peer, master) = match how {
            ms::SHARED if m.peer == 0 => (self.alloc_group(), m.master),
            ms::SHARED => (m.peer, m.master),
            ms::SLAVE if others => (0, m.peer),
            ms::SLAVE => (0, m.master),
            _ => (0, 0),
        };
        let Some(m) = self.get_mut(id) else { return };
        m.peer = peer;
        m.master = master;
        m.propagation = match (peer != 0, master != 0) {
            _ if how == ms::UNBINDABLE => ms::UNBINDABLE,
            (true, true) => ms::SHARED | ms::SLAVE,
            (true, false) => ms::SHARED,
            (false, true) => ms::SLAVE,
            (false, false) => ms::PRIVATE,
        };
    }

    /// `pivot_root(new_root, put_old)` for a process whose root is the
    /// root of the mount at `root` (a path in the namespace's view; `/`
    /// for the namespace's own root): the mount at `new_root` takes that
    /// mount's place, and that mount goes to `put_old` (a path under
    /// `new_root`). Returns where `put_old` is now.
    pub fn pivot_root(
        &mut self,
        root: &[u8],
        new_root: &[u8],
        put_old: &[u8],
    ) -> Result<Vec<u8>, i32> {
        // In Linux's order of checks.
        let (r, root_rest) = self.locate(root);
        let r = r.clone();
        let (n, new_rest) = self.locate(new_root);
        let n = n.clone();
        let o = self.locate(put_old).0.clone();
        let shared = |id: u32| self.get(id).is_some_and(|m| m.peer != 0);
        if o.peer != 0 || shared(n.parent) || (r.parent != r.id && shared(r.parent)) {
            return Err(errno::EINVAL);
        }
        if n.id == r.id || o.id == r.id {
            return Err(errno::EBUSY);
        }
        // The caller's root and the new one must be mounts' roots.
        if !root_rest.is_empty() || !new_rest.is_empty() {
            return Err(errno::EINVAL);
        }
        if !self.is_below(n.id, r.id) {
            return Err(errno::EINVAL);
        }
        // `put_old` must be in the new root's tree.
        let Some(put_rel) = under(put_old, &n.point) else { return Err(errno::EINVAL) };
        let (holder, _) = self.locate(put_old);
        let holder = holder.id;
        if holder != n.id && !self.is_below(holder, n.id) {
            return Err(errno::EINVAL);
        }
        let new_put = join(root, put_rel);
        let in_n = self.descendants(n.id);
        let in_r: Vec<u32> = self
            .descendants(r.id)
            .into_iter()
            .filter(|d| *d != n.id && !in_n.contains(d))
            .collect();
        let r_is_top = r.parent == r.id;
        for m in self.mounts.iter_mut() {
            if m.id == n.id {
                // Where the old root was (the namespace's root, if it was).
                m.parent = if r_is_top { n.id } else { r.parent };
                m.point = root.to_vec();
            } else if in_n.contains(&m.id) {
                m.point = join(root, under(&m.point, &n.point).unwrap_or(b""));
            } else if m.id == r.id {
                m.parent = holder;
                m.point = new_put.clone();
            } else if in_r.contains(&m.id) {
                m.point = join(&new_put, under(&m.point, root).unwrap_or(b""));
            }
        }
        Ok(new_put)
    }

    /// `/proc/self/mountinfo` for a process whose root is `root` (a path in
    /// the namespace's view): the mounts it can reach, in mount order, with
    /// their paths as it sees them.
    pub fn mountinfo(&self, root: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for m in &self.mounts {
            let Some(rel) = under(&m.point, root) else { continue };
            // Hidden under a mount stacked over it, or a parent.
            let point = if rel.is_empty() { b"/".to_vec() } else { rel.to_vec() };
            let parent = if m.parent == m.id { m.id } else { m.parent };
            let opts = m.mount_options();
            let mut optional = Vec::new();
            if m.peer != 0 {
                optional.extend_from_slice(format!(" shared:{}", m.peer).as_bytes());
            }
            if m.master != 0 {
                optional.extend_from_slice(format!(" master:{}", m.master).as_bytes());
            }
            if m.propagation & ms::UNBINDABLE != 0 {
                optional.extend_from_slice(b" unbindable");
            }
            let line = [
                format!("{} {} 0:{} ", m.id, parent, 20 + m.id).as_bytes(),
                &escape(&m.root),
                b" ",
                &escape(&point),
                b" ",
                &opts,
                &optional,
                b" - ",
                m.fstype.name().as_bytes(),
                b" ",
                &escape(&m.device),
                b" ",
                &escape(&m.options),
                b"\n",
            ]
            .concat();
            out.extend_from_slice(&line);
        }
        out
    }

    /// `/proc/self/mounts`, the older form.
    pub fn mounts_file(&self, root: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        for m in &self.mounts {
            let Some(rel) = under(&m.point, root) else { continue };
            let point = if rel.is_empty() { b"/".to_vec() } else { rel.to_vec() };
            // The mount's options, then its filesystem's.
            let mut opts = m.mount_options();
            for o in m.options.split(|&b| b == b',') {
                if !o.is_empty() && o != b"rw" && o != b"ro" {
                    opts.push(b',');
                    opts.extend_from_slice(o);
                }
            }
            let line = [
                &escape(&m.device),
                &b" "[..],
                &escape(&point),
                b" ",
                m.fstype.name().as_bytes(),
                b" ",
                &escape(&opts),
                b" 0 0\n",
            ]
            .concat();
            out.extend_from_slice(&line);
        }
        out
    }

    pub fn encode(&self, e: &mut crate::snapshot::Enc) {
        e.u32(self.next_id);
        e.u32(self.next_group);
        e.u64(self.mounts.len() as u64);
        for m in &self.mounts {
            e.u32(m.id);
            e.u32(m.parent);
            e.bytes(&m.point);
            e.u32(m.fstype.code());
            match &m.source {
                Source::Host(p) => {
                    e.u8(1);
                    e.bytes(p);
                }
                Source::Overlay(l) => {
                    e.u8(2);
                    l.encode(e);
                }
                Source::Synthetic => e.u8(0),
                Source::Ns(n) => {
                    e.u8(3);
                    e.u64(n.kind);
                    e.u64(n.id);
                    e.bool(n.dir.is_some());
                    e.bytes(n.dir.as_deref().unwrap_or_default());
                }
            }
            e.bytes(&m.root);
            e.u64(m.flags);
            e.u64(m.propagation);
            e.u32(m.peer);
            e.u32(m.master);
            e.bytes(&m.device);
            e.bytes(&m.options);
        }
        e.u64(self.expiring.len() as u64);
        for &id in &self.expiring {
            e.u32(id);
        }
        e.bytes(&self.owner);
    }

    pub fn decode(d: &mut crate::snapshot::Dec) -> Table {
        let (next_id, next_group) = (d.u32(), d.u32());
        // Each mount takes at least its fixed-size fields.
        let n = d.count(48);
        let mounts = (0..n)
            .map(|_| Mount {
                id: d.u32(),
                parent: d.u32(),
                point: d.bytes(),
                fstype: FsType::from_code(d.u32()),
                source: match d.u8() {
                    1 => Source::Host(d.bytes()),
                    2 => Source::Overlay(std::sync::Arc::new(crate::overlay::Layers::decode(d))),
                    3 => {
                        let (kind, id, has) = (d.u64(), d.u64(), d.bool());
                        let dir = d.bytes();
                        Source::Ns(crate::nsfd::NsRef { kind, id, dir: has.then_some(dir) })
                    }
                    _ => Source::Synthetic,
                },
                root: d.bytes(),
                flags: d.u64(),
                propagation: d.u64(),
                peer: d.u32(),
                master: d.u32(),
                device: d.bytes(),
                options: d.bytes(),
            })
            .collect();
        let n = d.count(4);
        let expiring = (0..n).map(|_| d.u32()).collect();
        let owner = d.bytes();
        Table { mounts, next_id, next_group, outbox: Vec::new(), expiring, owner }
    }
}

impl crate::shared::Data for Table {
    fn encode(&self, e: &mut crate::snapshot::Enc) {
        Table::encode(self, e);
    }
    fn decode(d: &mut crate::snapshot::Dec) -> Self {
        Table::decode(d)
    }
    fn valid(&self) -> bool {
        self.mounts.iter().any(|m| m.parent == m.id)
    }
}

/// A mount namespace's table where every process in the namespace finds
/// it: a shared record ([`crate::shared`]).
pub mod store {
    use super::{Propagation, Table, ms};
    use crate::shared::Record;
    use std::sync::Arc;

    /// The namespace identity Linux gives the initial mount namespace.
    pub const INIT_ID: u64 = 4026531841;

    /// One mount namespace, as this process sees it.
    #[derive(Debug)]
    pub struct Ns(Record<Table>);

    impl Ns {
        /// The initial namespace of the rootfs at `root_host`: every fwe
        /// process started on that root is in it, as every process on a
        /// machine starts in one. Made with [`Table::initial`] when new.
        pub fn initial(root_host: &[u8], shm_host: Option<&[u8]>) -> Result<Ns, i32> {
            let name = format!("mnt-init-{:016x}", crate::shared::hash(root_host));
            let cgroup = crate::cgroupfs::tree_dir().ok();
            Record::named(&name, INIT_ID, || Table::initial(root_host, shm_host, cgroup.as_deref()))
                .map(Ns)
        }

        /// A new namespace holding a copy of this one's mounts
        /// (`CLONE_NEWNS`), owned by the user namespace whose directory is
        /// `owner`. Owned by another than this one's, its shared mounts are
        /// slaves of theirs instead (Linux's `CL_SHARED_TO_SLAVE`): what a
        /// less privileged namespace mounts does not reach back.
        pub fn copy(&self, owner: &[u8]) -> Result<Ns, i32> {
            let mut t = (*self.table()).clone();
            if t.owner != owner {
                for m in t.mounts.iter_mut().filter(|m| m.peer != 0) {
                    m.master = m.peer;
                    m.peer = 0;
                    m.propagation = ms::SLAVE;
                }
                t.owner = owner.to_vec();
            }
            Record::fresh("mnt", t).map(Ns)
        }

        /// The namespace whose directory is `dir`, as [`Ns::dir`] gives it
        /// (in a process that inherited it).
        pub fn join(dir: &[u8], id: u64) -> Result<Ns, i32> {
            Record::join(dir, id).map(Ns)
        }

        pub fn dir(&self) -> &[u8] {
            self.0.dir()
        }

        pub fn id(&self) -> u64 {
            self.0.id()
        }

        /// The table's generation: every change moves it.
        pub fn generation(&self) -> u64 {
            self.0.generation()
        }

        /// The table as it is now.
        pub fn table(&self) -> Arc<Table> {
            self.0.get()
        }

        /// Change the table with `f`, for every process in the namespace,
        /// then carry what it propagates to the other namespaces.
        pub fn update<R>(&self, f: impl FnOnce(&mut Table) -> Result<R, i32>) -> Result<R, i32> {
            let mut out = Vec::new();
            let before = OWN.with(|o| o.replace(Some(self.dir().to_vec())));
            let r = self.0.update(|t| {
                let r = f(t);
                out = std::mem::take(&mut t.outbox);
                r
            });
            OWN.with(|o| o.replace(before));
            let r = r?;
            for ev in out {
                spread(self.dir(), &ev);
            }
            Ok(r)
        }
    }

    /// The count of peer groups, which every namespace's share.
    #[derive(Clone, Debug, Default)]
    struct Groups(u32);

    impl crate::shared::Data for Groups {
        fn encode(&self, e: &mut crate::snapshot::Enc) {
            e.u32(self.0);
        }
        fn decode(d: &mut crate::snapshot::Dec) -> Self {
            Groups(d.u32())
        }
    }

    /// A new peer group's id, unique across namespaces (so a group's
    /// members in two namespaces are known as one group).
    pub fn next_group() -> Option<u32> {
        static G: std::sync::OnceLock<Option<Record<Groups>>> = std::sync::OnceLock::new();
        let r = G.get_or_init(|| Record::named("mount-groups", 0, || Groups(1)).ok()).as_ref()?;
        r.update(|g| {
            let n = g.0.max(1);
            g.0 = n + 1;
            Ok(n)
        })
        .ok()
    }

    /// The mount namespaces live processes are in (and the initial ones),
    /// by their records' directories.
    fn namespaces() -> Vec<Vec<u8>> {
        let prefix = format!("v{}-mnt-", crate::shared::FORMAT);
        let mut out: Vec<Vec<u8>> = Vec::new();
        for (_, r) in crate::procreg::all() {
            for d in r.ns {
                let name = d.rsplit(|&b| b == b'/').next().unwrap_or_default();
                if name.starts_with(prefix.as_bytes()) && !out.contains(&d) {
                    out.push(d);
                }
            }
        }
        out
    }

    /// Carry propagation `ev`, made in the namespace at `own`, to every
    /// other namespace (which has, with every slave group it names, all it
    /// reaches there).
    fn spread(own: &[u8], ev: &Propagation) {
        for d in namespaces().into_iter().filter(|d| d != own) {
            // A namespace whose record cannot be read a moment (another
            // process replacing it) is tried again; one that still cannot
            // is said, as it misses the propagation.
            let mut tries = 0;
            let ns = loop {
                match Record::<Table>::join(&d, 0) {
                    Ok(ns) => break Some(ns),
                    // A namespace no process is in any more.
                    Err(_)
                        if !std::path::Path::new(
                            <std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(&d),
                        )
                        .exists() =>
                    {
                        break None;
                    }
                    Err(e) if tries == 10 => {
                        eprintln!(
                            "fwe: mount propagation to {} skipped: errno {e}",
                            String::from_utf8_lossy(&d)
                        );
                        break None;
                    }
                    Err(_) => {
                        tries += 1;
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                }
            };
            let Some(ns) = ns else { continue };
            let r = ns.update_maybe(|t| {
                let before = t.mounts.clone();
                t.receive(ev);
                Ok(((), t.mounts != before))
            });
            if let Err(e) = r {
                eprintln!(
                    "fwe: mount propagation to {} failed: errno {e}",
                    String::from_utf8_lossy(&d)
                );
            }
        }
    }

    std::thread_local! {
        /// The namespace whose table is being changed ([`Ns::update`]).
        static OWN: std::cell::RefCell<Option<Vec<u8>>> = const { std::cell::RefCell::new(None) };
    }

    /// The tables of the mount namespaces other than the one being changed
    /// (none outside a change): read, never locked, so a change reads them
    /// with its own namespace locked and no other.
    pub fn others() -> Vec<Arc<Table>> {
        let Some(own) = OWN.with(|o| o.borrow().clone()) else { return Vec::new() };
        namespaces()
            .into_iter()
            .filter(|d| *d != own)
            .filter_map(|d| Record::<Table>::join(&d, 0).ok().map(|r| r.get()))
            .collect()
    }
}

/// `mounts`, the copies under mount `root` of a tree, in an order where
/// each comes after the one it is attached to.
fn parent_first(root: u32, mut mounts: Vec<Mount>) -> Vec<Mount> {
    let mut placed = vec![root];
    let mut out = Vec::with_capacity(mounts.len());
    while !mounts.is_empty() {
        let before = mounts.len();
        let (ready, rest): (Vec<Mount>, Vec<Mount>) =
            mounts.into_iter().partition(|m| placed.contains(&m.parent));
        placed.extend(ready.iter().map(|m| m.id));
        out.extend(ready);
        mounts = rest;
        if mounts.len() == before {
            // Attached to nothing copied: left out, as a copy has no place
            // for them.
            break;
        }
    }
    out
}

/// A path as `mountinfo` writes it: space, tab, newline and backslash as
/// octal escapes.
fn escape(p: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(p.len());
    for &b in p {
        match b {
            b' ' | b'\t' | b'\n' | b'\\' => out.extend_from_slice(format!("\\{b:03o}").as_bytes()),
            _ => out.push(b),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> Table {
        Table::initial(b"/host/root", Some(b"/host/shm"), Some(b"/host/cgroup"))
    }

    fn tmpfs(t: &mut Table, at: &[u8]) -> u32 {
        t.mount(
            at,
            FsType::Tmpfs,
            Source::Host(at.to_vec()),
            b"/".to_vec(),
            0,
            b"tmpfs".to_vec(),
            vec![],
        )
    }

    #[test]
    fn locates_paths_through_mounts() {
        let t = table();
        let (m, rest) = t.locate(b"/etc/passwd");
        assert_eq!((m.fstype, rest.as_slice()), (FsType::Ext4, &b"/etc/passwd"[..]));
        assert_eq!(m.host_path(&rest).unwrap(), b"/host/root/etc/passwd");
        let (m, rest) = t.locate(b"/proc/self/exe");
        assert_eq!((m.fstype, rest.as_slice()), (FsType::Proc, &b"/self/exe"[..]));
        let (m, rest) = t.locate(b"/sys/fs/cgroup");
        assert_eq!((m.fstype, rest.as_slice()), (FsType::Cgroup2, &b""[..]));
        let (m, _) = t.locate(b"/sys/fs");
        assert_eq!(m.fstype, FsType::Sysfs);
        let (m, rest) = t.locate(b"/dev/shm/x");
        assert_eq!(m.host_path(&rest).unwrap(), b"/host/shm/x");
    }

    /// Peer groups as Linux keeps them: a bind of a shared mount is its
    /// peer, a slave receives from the group it left, and `mountinfo`
    /// shows both.
    #[test]
    fn peer_groups_follow_binds_and_changes() {
        let mut t = table();
        let a = tmpfs(&mut t, b"/a");
        t.set_propagation(b"/a", ms::SHARED, false).unwrap();
        let group = t.get(a).unwrap().peer;
        assert_ne!(group, 0);
        let b = t.bind(b"/a", b"/b", false, 0).unwrap();
        assert_eq!(t.get(b).unwrap().peer, group);
        t.set_propagation(b"/b", ms::SLAVE, false).unwrap();
        let bm = t.get(b).unwrap();
        assert_eq!((bm.peer, bm.master, bm.propagation), (0, group, ms::SLAVE));
        let info = String::from_utf8(t.mountinfo(b"/")).unwrap();
        assert!(info.lines().any(|l| l.contains(" /a ") && l.contains(&format!("shared:{group}"))));
        assert!(info.lines().any(|l| l.contains(" /b ") && l.contains(&format!("master:{group}"))));
        // The last of a group, made a slave, has no one to receive from.
        t.set_propagation(b"/a", ms::SLAVE, false).unwrap();
        assert_eq!(t.get(a).unwrap().propagation, ms::PRIVATE);
        // A new mount under a shared one is shared, in a group of its own.
        t.set_propagation(b"/b", ms::SHARED, false).unwrap();
        let c = tmpfs(&mut t, b"/b/c");
        let peer = t.get(c).unwrap().peer;
        assert!(peer != 0 && peer != t.get(b).unwrap().peer);
    }

    /// A detached copy attaches elsewhere, and beneath a mount: between it
    /// and what it was attached to.
    #[test]
    fn detached_trees_attach_and_go_beneath() {
        let mut t = table();
        tmpfs(&mut t, b"/a");
        tmpfs(&mut t, b"/a/sub");
        let top = tmpfs(&mut t, b"/b");
        let tree = t.copy_tree(b"/a", true).unwrap();
        assert_eq!(tree.len(), 2);
        assert_eq!(tree[1].point, b"/sub");
        let copy = t.attach_tree(&tree, b"/c", false).unwrap();
        assert_eq!(t.locate(b"/c/sub/x").0.point, b"/c/sub");
        assert_ne!(t.locate(b"/c/sub/x").0.id, t.locate(b"/a/sub/x").0.id);
        assert!(t.get(copy).is_some());
        // Beneath /b: /b still shows on top, and unmounting it uncovers
        // the copy.
        let under = t.attach_tree(&tree[..1], b"/b", true).unwrap();
        assert_eq!(t.locate(b"/b/x").0.id, top);
        assert_eq!(t.get(top).unwrap().parent, under);
        t.umount(b"/b").unwrap();
        assert_eq!(t.locate(b"/b/x").0.id, under);
        // Not beneath the root, nor beneath a path that is no mount's root.
        assert_eq!(t.attach_tree(&tree, b"/", true), Err(errno::EINVAL));
        assert_eq!(t.attach_tree(&tree, b"/b/x", true), Err(errno::EINVAL));
    }

    /// An attached mount moved beneath another keeps its id, and a
    /// recursive copy then keeps both, in order.
    #[test]
    fn a_mount_moved_beneath_keeps_its_id() {
        let mut t = table();
        tmpfs(&mut t, b"/a");
        let top = tmpfs(&mut t, b"/a/b");
        let n = tmpfs(&mut t, b"/n");
        t.move_beneath(b"/n", b"/a/b").unwrap();
        assert_eq!(t.get(n).unwrap().point, b"/a/b");
        assert_eq!(t.get(top).unwrap().parent, n);
        assert_eq!(t.locate(b"/a/b/x").0.id, top);
        let tree = t.copy_tree(b"/a", true).unwrap();
        t.attach_tree(&tree, b"/c", false).unwrap();
        let shown = t.locate(b"/c/b/x").0;
        assert_eq!((shown.point.as_slice(), shown.parent != top), (&b"/c/b"[..], true));
        assert_eq!(t.locate(b"/c/b").0.source, t.get(top).unwrap().source);
    }

    /// When the last of a group leaves it, its slaves receive from what it
    /// received from: here nothing, so they are private.
    #[test]
    fn slaves_of_a_dissolved_group_go_private() {
        let mut t = table();
        let a = tmpfs(&mut t, b"/a");
        t.set_propagation(b"/a", ms::SHARED, false).unwrap();
        let b = t.bind(b"/a", b"/b", false, 0).unwrap();
        t.set_propagation(b"/b", ms::SLAVE, false).unwrap();
        assert_ne!(t.get(b).unwrap().master, 0);
        t.set_propagation(b"/a", ms::PRIVATE, false).unwrap();
        let bm = t.get(b).unwrap();
        assert_eq!((bm.master, bm.propagation), (0, ms::PRIVATE));
        assert_eq!(t.get(a).unwrap().peer, 0);
    }

    /// What is mounted under a shared mount reaches its peers and its
    /// slaves, a slave's mounts do not reach its master, and an unmount
    /// takes the copies with it.
    #[test]
    fn mounts_propagate_to_peers_and_slaves() {
        let mut t = table();
        tmpfs(&mut t, b"/a");
        t.set_propagation(b"/a", ms::SHARED, false).unwrap();
        t.bind(b"/a", b"/b", false, 0).unwrap();
        t.bind(b"/a", b"/s", false, 0).unwrap();
        t.set_propagation(b"/s", ms::SLAVE, false).unwrap();
        tmpfs(&mut t, b"/a/x");
        let x = t.locate(b"/a/x/f").0.clone();
        assert_eq!(x.point, b"/a/x");
        let bx = t.locate(b"/b/x/f").0.clone();
        let sx = t.locate(b"/s/x/f").0.clone();
        assert_eq!((bx.point.as_slice(), bx.peer), (&b"/b/x"[..], x.peer));
        assert_eq!((sx.point.as_slice(), sx.peer, sx.master), (&b"/s/x"[..], 0, x.peer));
        // A slave's own mount stays its own.
        tmpfs(&mut t, b"/s/y");
        assert_eq!(t.locate(b"/a/y/f").0.point, b"/a");
        // Unmounted from one peer, gone from all.
        t.umount(b"/b/x").unwrap();
        assert_eq!(t.locate(b"/a/x/f").0.point, b"/a");
        assert_eq!(t.locate(b"/s/x/f").0.point, b"/s");
    }

    /// A namespace copied from another (`CLONE_NEWNS`) has peers of its
    /// shared mounts: a mount in one reaches the other, and its unmount
    /// takes the copy away.
    #[test]
    fn propagation_reaches_a_copied_namespace() {
        let mut a = table();
        tmpfs(&mut a, b"/m");
        a.set_propagation(b"/m", ms::SHARED, false).unwrap();
        let mut b = a.clone();
        a.outbox.clear();
        tmpfs(&mut a, b"/m/x");
        let ev = a.outbox.pop().expect("an attach to carry");
        b.receive(&ev);
        let got = b.locate(b"/m/x/f").0.clone();
        assert_eq!((got.point.as_slice(), got.peer), (&b"/m/x"[..], a.locate(b"/m/x/f").0.peer));
        a.umount(b"/m/x").unwrap();
        let ev = a.outbox.pop().expect("a detach to carry");
        b.receive(&ev);
        assert_eq!(b.locate(b"/m/x/f").0.point, b"/m");
    }

    /// A shared slave of a shared mount, in two namespaces: what is mounted
    /// under the master reaches the slave once in each, and the copies in
    /// the slave's group are peers of each other, slaves of the new mount.
    #[test]
    fn propagation_reaches_shared_slaves_once() {
        let mut a = table();
        tmpfs(&mut a, b"/m");
        a.set_propagation(b"/m", ms::SHARED, false).unwrap();
        a.bind(b"/m", b"/n", false, 0).unwrap();
        a.set_propagation(b"/n", ms::SLAVE, false).unwrap();
        a.set_propagation(b"/n", ms::SHARED, false).unwrap();
        a.bind(b"/n", b"/o", false, 0).unwrap();
        let mut b = a.clone();
        a.outbox.clear();
        tmpfs(&mut a, b"/m/x");
        let ev = a.outbox.pop().expect("an attach to carry");
        b.receive(&ev);
        for t in [&a, &b] {
            for at in [&b"/m/x"[..], b"/n/x", b"/o/x"] {
                assert_eq!(t.mounts.iter().filter(|m| m.point == at).count(), 1, "{at:?}");
            }
            let x = t.locate(b"/m/x/f").0.peer;
            let (n, o) = (t.locate(b"/n/x/f").0.clone(), t.locate(b"/o/x/f").0.clone());
            assert_eq!((n.master, o.master), (x, x));
            assert!(n.peer != 0 && n.peer == o.peer && n.peer != x);
        }
        assert_eq!(a.locate(b"/n/x/f").0.peer, b.locate(b"/n/x/f").0.peer);
    }

    /// Unmounting a tree from a shared mount takes its copies from the
    /// peers, what is under them included, and a mount stacked on a copy
    /// takes its place.
    #[test]
    fn unmounts_take_copied_trees() {
        let mut t = table();
        tmpfs(&mut t, b"/a");
        t.set_propagation(b"/a", ms::SHARED, false).unwrap();
        t.bind(b"/a", b"/b", false, 0).unwrap();
        tmpfs(&mut t, b"/a/x");
        tmpfs(&mut t, b"/a/x/y");
        assert_eq!(t.locate(b"/b/x/y/f").0.point, b"/b/x/y");
        t.umount(b"/a/x").unwrap();
        assert_eq!(t.locate(b"/b/x/y/f").0.point, b"/b");
        // A slave's own mount, which a copy goes beneath.
        t.set_propagation(b"/b", ms::SLAVE, false).unwrap();
        let own = tmpfs(&mut t, b"/b/x");
        tmpfs(&mut t, b"/a/x");
        assert_ne!(t.locate(b"/b/x/f").0.parent, t.locate(b"/b/f").0.id);
        t.umount(b"/a/x").unwrap();
        let got = t.locate(b"/b/x/f").0.clone();
        assert_eq!((got.id, got.parent), (own, t.locate(b"/b/f").0.id));
    }

    /// A namespace copied into another user namespace has slaves of the
    /// old one's shared mounts.
    #[test]
    fn a_less_privileged_copy_is_a_slave() {
        let root = format!("/fwe-test-root-owner-{}", std::process::id());
        let a = store::Ns::initial(root.as_bytes(), None).unwrap();
        a.update(|t| {
            tmpfs(t, b"/mnt");
            t.set_propagation(b"/mnt", ms::SHARED, false)
        })
        .unwrap();
        let g = a.table().locate(b"/mnt").0.peer;
        let c = a.copy(b"/some/user/ns").unwrap();
        let m = c.table().locate(b"/mnt").0.clone();
        assert_eq!((m.peer, m.master, m.propagation), (0, g, ms::SLAVE));
        for d in [a.dir(), c.dir()] {
            let _ = std::fs::remove_dir_all(String::from_utf8_lossy(d).as_ref());
        }
    }

    /// A bind of a shared mount onto itself doubles what is there, each
    /// copy going beneath the mount already there (Linux's tucking).
    #[test]
    fn binds_onto_a_shared_mount_double() {
        let mut t = table();
        tmpfs(&mut t, b"/r");
        t.set_propagation(b"/r", ms::SHARED, false).unwrap();
        for _ in 0..3 {
            t.bind(b"/r", b"/r", false, 0).unwrap();
        }
        assert_eq!(t.mounts.iter().filter(|m| m.point == b"/r").count(), 8);
    }

    /// Unique ids sit above every old one.
    #[test]
    fn unique_ids_find_mounts() {
        let mut t = table();
        let a = tmpfs(&mut t, b"/a");
        let u = t.get(a).unwrap().unique_id();
        assert!(u > UNIQUE_ID_BASE);
        assert_eq!(t.by_unique(u).unwrap().id, a);
    }

    /// Mounts stack, and unmounting one uncovers what it covered.
    #[test]
    fn mounts_stack_and_unmount() {
        let mut t = table();
        tmpfs(&mut t, b"/mnt");
        let top = tmpfs(&mut t, b"/mnt");
        assert_eq!(t.locate(b"/mnt/a").0.id, top);
        tmpfs(&mut t, b"/mnt/sub");
        t.umount(b"/mnt").unwrap();
        let (m, _) = t.locate(b"/mnt/sub/x");
        assert_eq!(m.fstype, FsType::Tmpfs);
        assert_ne!(m.id, top);
        t.umount(b"/mnt").unwrap();
        assert_eq!(t.locate(b"/mnt").0.fstype, FsType::Ext4);
        assert_eq!(t.umount(b"/mnt"), Err(errno::EINVAL));
        assert_eq!(t.umount(b"/"), Err(errno::EINVAL));
    }

    /// A bind mount shows the source's files, and a recursive one the
    /// mounts under it.
    #[test]
    fn bind_mounts() {
        let mut t = table();
        tmpfs(&mut t, b"/srv/data");
        t.bind(b"/srv", b"/mnt", false, 0).unwrap();
        let (m, rest) = t.locate(b"/mnt/data/f");
        assert_eq!(m.host_path(&rest).unwrap(), b"/host/root/srv/data/f");
        t.bind(b"/srv", b"/rec", true, ms::RDONLY).unwrap();
        let (m, rest) = t.locate(b"/rec/data/f");
        assert_eq!(
            (m.fstype, m.host_path(&rest).unwrap()),
            (FsType::Tmpfs, b"/srv/data/f".to_vec())
        );
        assert!(t.locate(b"/rec").0.read_only());
        t.bind(b"/proc/sys", b"/proc/sys", false, 0).unwrap();
        t.remount(b"/proc/sys", ms::RDONLY, None).unwrap();
        let (m, rest) = t.locate(b"/proc/sys/kernel");
        assert!(m.read_only() && m.fstype == FsType::Proc);
        assert_eq!(m.fs_path(&rest), b"/sys/kernel");
        assert!(!t.locate(b"/proc/self").0.read_only());
    }

    /// The `pivot_root(".", ".")` a container runtime makes, then the
    /// unmount of the old root stacked on top.
    #[test]
    fn pivot_root_into_a_container() {
        let mut t = table();
        t.bind(b"/bundle/rootfs", b"/bundle/rootfs", false, 0).unwrap();
        t.mount(
            b"/bundle/rootfs/proc",
            FsType::Proc,
            Source::Synthetic,
            b"/".to_vec(),
            0,
            b"proc".to_vec(),
            vec![],
        );
        tmpfs(&mut t, b"/bundle/rootfs/dev");
        let old = t.pivot_root(b"/", b"/bundle/rootfs", b"/bundle/rootfs").unwrap();
        assert_eq!(old, b"/");
        // The old root is stacked over the new one until unmounted.
        assert_eq!(t.locate(b"/etc").0.host_path(b"/etc").unwrap(), b"/host/root/etc");
        t.umount(b"/").unwrap();
        let (m, rest) = t.locate(b"/etc/os-release");
        assert_eq!(m.host_path(&rest).unwrap(), b"/host/root/bundle/rootfs/etc/os-release");
        assert_eq!(t.locate(b"/proc/1").0.fstype, FsType::Proc);
        assert_eq!(t.locate(b"/dev/null").0.fstype, FsType::Tmpfs);
        assert_eq!(t.locate(b"/sys").0.fstype, FsType::Ext4);
        assert_eq!(t.mounts.len(), 3);
        let info = String::from_utf8(t.mountinfo(b"/")).unwrap();
        assert!(info.lines().next().unwrap().contains(" /bundle/rootfs / rw"), "{info}");
    }

    /// `pivot_root` to a separate `put_old`.
    #[test]
    fn pivot_root_with_put_old() {
        let mut t = table();
        tmpfs(&mut t, b"/new");
        let old = t.pivot_root(b"/", b"/new", b"/new/old").unwrap();
        assert_eq!(old, b"/old");
        assert_eq!(t.locate(b"/x").0.fstype, FsType::Tmpfs);
        let (m, rest) = t.locate(b"/old/etc");
        assert_eq!(m.host_path(&rest).unwrap(), b"/host/root/etc");
        assert_eq!(t.locate(b"/old/proc/self").0.fstype, FsType::Proc);
        t.umount(b"/old").unwrap();
        assert_eq!(t.mounts.len(), 1);
    }

    /// Two handles on one namespace, as two processes have: a change made
    /// through one is seen through the other, and a copy is separate.
    #[test]
    fn shared_between_processes() {
        let root = format!("/fwe-test-root-{}", std::process::id());
        let a = store::Ns::initial(root.as_bytes(), None).unwrap();
        let b = store::Ns::join(a.dir(), a.id()).unwrap();
        assert_eq!(a.id(), store::INIT_ID);
        a.update(|t| {
            tmpfs(t, b"/mnt");
            Ok(())
        })
        .unwrap();
        assert_eq!(b.table().locate(b"/mnt").0.fstype, FsType::Tmpfs);
        let c = b.copy(b"").unwrap();
        assert_ne!(c.id(), a.id());
        c.update(|t| t.umount(b"/mnt")).unwrap();
        assert_eq!(c.table().locate(b"/mnt").0.fstype, FsType::Ext4);
        assert_eq!(a.table().locate(b"/mnt").0.fstype, FsType::Tmpfs);
        for d in [a.dir(), c.dir()] {
            let _ = std::fs::remove_dir_all(String::from_utf8_lossy(d).as_ref());
        }
    }

    #[test]
    fn moves_and_round_trips() {
        let mut t = table();
        tmpfs(&mut t, b"/a");
        tmpfs(&mut t, b"/a/b");
        t.move_mount(b"/a", b"/c").unwrap();
        assert_eq!(t.locate(b"/c/b/x").0.point, b"/c/b");
        assert_eq!(t.locate(b"/a").0.fstype, FsType::Ext4);
        assert_eq!(t.move_mount(b"/c", b"/c/b/d"), Err(errno::ELOOP));
        let mut e = crate::snapshot::Enc::new();
        t.encode(&mut e);
        let bytes = e.into_bytes();
        let mut d = crate::snapshot::Dec::new(&bytes);
        assert_eq!(Table::decode(&mut d), t);
    }
}
