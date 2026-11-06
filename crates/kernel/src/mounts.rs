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
    /// Propagation (`MS_SHARED`, `MS_SLAVE`, `MS_PRIVATE` or
    /// `MS_UNBINDABLE`); recorded, not acted on.
    pub propagation: u64,
    /// The source as `mount` was given it, for `mountinfo`.
    pub device: Vec<u8>,
    /// The filesystem's options (`mode=755` and the like).
    pub options: Vec<u8>,
}

impl Mount {
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
}

impl Table {
    /// The table a namespace starts with when nothing was mounted in it:
    /// the rootfs at `root_host` and what Linux always has mounted.
    pub fn initial(root_host: &[u8], shm_host: Option<&[u8]>, cgroup_host: Option<&[u8]>) -> Table {
        let mut t = Table { mounts: Vec::new(), next_id: 1 };
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

    /// Attach a new mount at `point`, onto whatever `point` resolves to.
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
        // Onto the mount `point` is in; onto the one whose root it is, for a
        // mount stacked over another.
        let parent = self.locate(point).0.id;
        let propagation = self.get(parent).map_or(ms::PRIVATE, |p| {
            // A new mount under a shared one is shared, else private.
            if p.propagation & ms::SHARED != 0 { ms::SHARED } else { ms::PRIVATE }
        });
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
            device,
            options,
        });
        id
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
        let id = self.mount(
            to,
            src.fstype,
            src.source.clone(),
            src.fs_path(&rest),
            (src.flags & !ms::RDONLY) | (flags & ms::RDONLY),
            src.device.clone(),
            src.options.clone(),
        );
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
            let mut below = below;
            below.sort_by_key(|m| m.point.len());
            for m in below {
                let Some(&(_, parent)) = copies.iter().find(|(o, _)| *o == m.parent) else {
                    continue;
                };
                let point = join(to, under(&m.point, from).unwrap_or(b""));
                let copy = self.alloc();
                self.mounts.push(Mount { id: copy, parent, point, ..m.clone() });
                copies.push((m.id, copy));
            }
        }
        Ok(id)
    }

    /// Whether mount `id` is below mount `ancestor`.
    fn is_below(&self, mut id: u32, ancestor: u32) -> bool {
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
    /// it. `EINVAL` if `path` is not a mount's root.
    pub fn umount(&mut self, path: &[u8]) -> Result<(), i32> {
        let (m, rest) = self.locate(path);
        if !rest.is_empty() || m.parent == m.id {
            return Err(errno::EINVAL);
        }
        let id = m.id;
        let mut gone = self.descendants(id);
        gone.push(id);
        self.mounts.retain(|m| !gone.contains(&m.id));
        Ok(())
    }

    /// Move the mount whose root is `from` to `to`.
    pub fn move_mount(&mut self, from: &[u8], to: &[u8]) -> Result<(), i32> {
        let (m, rest) = self.locate(from);
        if !rest.is_empty() || m.parent == m.id {
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
        Ok(())
    }

    /// Change the per-mount flags of the mount whose root is `path`, and
    /// its filesystem's options if `data` is given. A remount of a
    /// filesystem acts on the one mount: what is mounted twice is two
    /// separate filesystems here.
    pub fn remount(&mut self, path: &[u8], flags: u64, data: Option<Vec<u8>>) -> Result<(), i32> {
        let (m, rest) = self.locate(path);
        if !rest.is_empty() {
            return Err(errno::EINVAL);
        }
        let id = m.id;
        let m = self.mounts.iter_mut().find(|m| m.id == id).unwrap();
        m.flags = flags & ms::PER_MOUNT;
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
        for m in self.mounts.iter_mut().filter(|m| ids.contains(&m.id)) {
            m.propagation = how & ms::PROPAGATION;
        }
        Ok(())
    }

    /// `pivot_root(new_root, put_old)`: the mount whose root is `new_root`
    /// becomes the namespace's root, and the old root goes to `put_old`
    /// (a path under `new_root`). Paths are in the old view; returns
    /// `put_old` in the new one.
    pub fn pivot_root(&mut self, new_root: &[u8], put_old: &[u8]) -> Result<Vec<u8>, i32> {
        let (new, rest) = self.locate(new_root);
        if !rest.is_empty() {
            return Err(errno::EINVAL);
        }
        let old = self.root().clone();
        if new.id == old.id {
            return Err(errno::EBUSY);
        }
        let new = new.clone();
        let Some(old_rel) = under(put_old, new_root) else { return Err(errno::EINVAL) };
        let old_point = if old_rel.is_empty() { b"/".to_vec() } else { old_rel.to_vec() };
        // `put_old` must be in the new root's tree.
        let (holder, _) = self.locate(put_old);
        let holder = holder.id;
        if holder != new.id && !self.is_below(holder, new.id) {
            return Err(errno::EINVAL);
        }
        let in_new = self.descendants(new.id);
        let new_point = new.point.clone();
        for m in self.mounts.iter_mut() {
            if m.id == new.id {
                m.parent = m.id;
                m.point = b"/".to_vec();
            } else if in_new.contains(&m.id) {
                m.point = join(b"/", under(&m.point, &new_point).unwrap_or(b""));
            } else {
                // The old tree moves under `put_old`.
                m.point = join(&old_point, &m.point);
            }
        }
        // The old root, until now its own parent, hangs from the mount
        // holding `put_old` in the new tree. The bottom mount at `/` of the
        // old tree (the old root may be a stack) is the one re-parented.
        let bottom = self.mounts.iter().find(|m| m.id == m.parent && m.id != new.id).map(|m| m.id);
        if let Some(b) = bottom {
            let m = self.mounts.iter_mut().find(|m| m.id == b).unwrap();
            m.parent = holder;
        }
        Ok(old_point)
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
            let mut opts = if m.read_only() { b"ro".to_vec() } else { b"rw".to_vec() };
            for (flag, name) in [
                (ms::NOSUID, &b"nosuid"[..]),
                (ms::NODEV, b"nodev"),
                (ms::NOEXEC, b"noexec"),
                (ms::NOATIME, b"noatime"),
                (ms::NODIRATIME, b"nodiratime"),
                (ms::RELATIME, b"relatime"),
            ] {
                if m.flags & flag != 0 {
                    opts.push(b',');
                    opts.extend_from_slice(name);
                }
            }
            let optional: &[u8] = match m.propagation {
                p if p & ms::SHARED != 0 => b" shared:1",
                p if p & ms::SLAVE != 0 => b" master:1",
                p if p & ms::UNBINDABLE != 0 => b" unbindable",
                _ => b"",
            };
            let line = [
                format!("{} {} 0:{} ", m.id, parent, 20 + m.id).as_bytes(),
                &escape(&m.root),
                b" ",
                &escape(&point),
                b" ",
                &opts,
                optional,
                b" - ",
                m.fstype.name().as_bytes(),
                b" ",
                &escape(&m.device),
                b" ",
                &m.options,
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
            let ro = if m.read_only() { "ro" } else { "rw" };
            let line = [
                &escape(&m.device),
                &b" "[..],
                &escape(&point),
                b" ",
                m.fstype.name().as_bytes(),
                b" ",
                ro.as_bytes(),
                b" 0 0\n",
            ]
            .concat();
            out.extend_from_slice(&line);
        }
        out
    }

    pub fn encode(&self, e: &mut crate::snapshot::Enc) {
        e.u32(self.next_id);
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
            }
            e.bytes(&m.root);
            e.u64(m.flags);
            e.u64(m.propagation);
            e.bytes(&m.device);
            e.bytes(&m.options);
        }
    }

    pub fn decode(d: &mut crate::snapshot::Dec) -> Table {
        let next_id = d.u32();
        // Each mount takes at least its fixed-size fields.
        let n = d.count(40);
        let mounts = (0..n)
            .map(|_| Mount {
                id: d.u32(),
                parent: d.u32(),
                point: d.bytes(),
                fstype: FsType::from_code(d.u32()),
                source: match d.u8() {
                    1 => Source::Host(d.bytes()),
                    2 => Source::Overlay(std::sync::Arc::new(crate::overlay::Layers::decode(d))),
                    _ => Source::Synthetic,
                },
                root: d.bytes(),
                flags: d.u64(),
                propagation: d.u64(),
                device: d.bytes(),
                options: d.bytes(),
            })
            .collect();
        Table { mounts, next_id }
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
    use super::Table;
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
        /// (`CLONE_NEWNS`).
        pub fn copy(&self) -> Result<Ns, i32> {
            Record::fresh("mnt", (*self.table()).clone()).map(Ns)
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

        /// The table as it is now.
        pub fn table(&self) -> Arc<Table> {
            self.0.get()
        }

        /// Change the table with `f`, for every process in the namespace.
        pub fn update<R>(&self, f: impl FnOnce(&mut Table) -> Result<R, i32>) -> Result<R, i32> {
            self.0.update(f)
        }
    }
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
        let old = t.pivot_root(b"/bundle/rootfs", b"/bundle/rootfs").unwrap();
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
        let old = t.pivot_root(b"/new", b"/new/old").unwrap();
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
        let c = b.copy().unwrap();
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
