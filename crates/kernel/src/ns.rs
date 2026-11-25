//! Namespaces other than the mount namespace (which [`crate::fs::Fs`]
//! holds): UTS, IPC, network, cgroup and pid.
//!
//! A process in a namespace it did not make for itself shares it with
//! others, so each namespace fwe makes is a shared record
//! ([`crate::shared`]). A process in the initial namespace of a kind has
//! `None` for it: that namespace is the host's, as Linux's initial ones are
//! the machine's — the host name, the host's pids.

use crate::shared::{self, Data, Record};
use crate::snapshot::{Dec, Enc};
use fwe_abi::clone::*;
use fwe_abi::errno;
use std::sync::Arc;

/// Identities Linux gives the initial namespaces.
pub const INIT_UTS: u64 = 4026531838;
pub const INIT_IPC: u64 = 4026531839;
pub const INIT_NET: u64 = 4026531840;
pub const INIT_PID: u64 = 4026531836;
pub const INIT_USER: u64 = 4026531837;
pub const INIT_CGROUP: u64 = 4026531835;

/// A UTS namespace: the host and domain names.
#[derive(Clone, Default, Debug)]
pub struct Uts {
    pub hostname: Vec<u8>,
    pub domainname: Vec<u8>,
}

impl Data for Uts {
    fn encode(&self, e: &mut Enc) {
        e.bytes(&self.hostname);
        e.bytes(&self.domainname);
    }
    fn decode(d: &mut Dec) -> Self {
        Uts { hostname: d.bytes(), domainname: d.bytes() }
    }
}

/// An IPC namespace's objects (System V IPC).
pub use crate::sysvipc::Ipc;

/// A network namespace: a loopback interface only, and its own ports
/// ([`crate::netns`]).
#[derive(Clone, Default, Debug)]
pub struct Net {
    /// Whether `lo` is up (a new namespace's is down).
    pub lo_up: bool,
    /// Each bound port, by protocol (6, 17) and number, and the host
    /// loopback port behind it.
    pub ports: std::collections::BTreeMap<(u8, u16), u16>,
    /// Its sysctls set (see [`crate::sysctl`]), by path under `/proc/sys`.
    pub sysctls: std::collections::BTreeMap<String, String>,
    /// `lo`'s MTU set (`SIOCSIFMTU`; 0: Linux's 65536).
    pub lo_mtu: u32,
    /// Whether `lo` has its IPv4 address, 127.0.0.1/8, and its IPv6 one,
    /// ::1/128 ([`Net::set_lo_up`], `RTM_NEWADDR`).
    pub lo_v4: bool,
    pub lo_v6: bool,
}

impl Net {
    /// `lo` brought up or down, as Linux's is: brought up, it has both its
    /// addresses; down, it keeps the IPv4 one and loses ::1.
    pub fn set_lo_up(&mut self, up: bool) {
        self.lo_up = up;
        self.lo_v4 |= up;
        self.lo_v6 = up;
    }
}

impl Data for Net {
    fn encode(&self, e: &mut Enc) {
        e.bool(self.lo_up);
        e.u64(self.ports.len() as u64);
        for ((p, port), host) in &self.ports {
            e.u8(*p);
            e.u32(u32::from(*port));
            e.u32(u32::from(*host));
        }
        e.u64(self.sysctls.len() as u64);
        for (k, v) in &self.sysctls {
            e.bytes(k.as_bytes());
            e.bytes(v.as_bytes());
        }
        e.u32(self.lo_mtu);
        e.bool(self.lo_v4);
        e.bool(self.lo_v6);
    }
    fn decode(d: &mut Dec) -> Self {
        let lo_up = d.bool();
        let n = d.count(9);
        let ports = (0..n).map(|_| ((d.u8(), d.u32() as u16), d.u32() as u16)).collect();
        let n = d.count(16);
        let text = |d: &mut Dec| String::from_utf8_lossy(&d.bytes()).into_owned();
        let sysctls = (0..n).map(|_| (text(d), text(d))).collect();
        let lo_mtu = d.u32();
        let (lo_v4, lo_v6) = (d.bool(), d.bool());
        Net { lo_up, ports, sysctls, lo_mtu, lo_v4, lo_v6 }
    }
}

/// A cgroup namespace: the cgroup that is its root.
#[derive(Clone, Default, Debug)]
pub struct Cgroup {
    pub root: Vec<u8>,
}

impl Data for Cgroup {
    fn encode(&self, e: &mut Enc) {
        e.bytes(&self.root);
    }
    fn decode(d: &mut Dec) -> Self {
        Cgroup { root: d.bytes() }
    }
}

/// A process's namespaces, `None` for the initial (the host's) ones.
#[derive(Clone, Default, Debug)]
pub struct Namespaces {
    pub uts: Option<Arc<Record<Uts>>>,
    pub ipc: Option<Arc<Record<Ipc>>>,
    pub net: Option<Arc<Record<Net>>>,
    pub cgroup: Option<Arc<Record<Cgroup>>>,
    /// The pid namespace the process is in.
    pub pid: Option<Arc<Record<crate::pidns::PidNs>>>,
    /// The one its children will be in (another after
    /// `unshare(CLONE_NEWPID)`).
    pub pid_children: Option<Arc<Record<crate::pidns::PidNs>>>,
    /// The user namespace.
    pub user: Option<Arc<Record<crate::userns::UserNs>>>,
}

/// Whether the record at `dir` is a namespace of kind `name` (`mnt`,
/// `uts`...) that one of fwe's calls made, not an initial one.
fn of_kind(dir: &[u8], name: &str) -> bool {
    let base = dir.rsplit(|&b| b == b'/').next().unwrap_or_default();
    let prefix = format!("v{}-{name}-", crate::shared::FORMAT);
    base.starts_with(prefix.as_bytes()) && !base[prefix.len()..].starts_with(b"init-")
}

/// Record that the namespace whose record is `dir` belongs to the user
/// namespace `user` (`None`: the initial one), in the note beside its
/// data ([`crate::shared::set_note`]): what `NS_GET_USERNS` gives and the
/// namespace limits count it against.
pub fn set_owner(dir: &[u8], user: Option<&Record<crate::userns::UserNs>>) {
    let text =
        user.map_or_else(Vec::new, |u| [u.dir(), format!("\n{}", u.id()).as_bytes()].concat());
    let _ = crate::shared::set_note(dir, &text);
}

/// The user namespace that owns the namespace whose record is `dir`: its
/// record's name and identity (`None`: the initial one).
pub fn owner_of(dir: &[u8]) -> Option<(Vec<u8>, u64)> {
    let text = crate::shared::note(dir)?;
    let nl = text.iter().rposition(|&b| b == b'\n')?;
    let id = std::str::from_utf8(&text[nl + 1..]).ok()?.parse().ok()?;
    Some((text[..nl].to_vec(), id))
}

/// The process's UTS namespace, for a write to `/proc/sys/kernel/hostname`
/// ([`set_current_name`]).
static UTS: std::sync::Mutex<Option<Arc<Record<Uts>>>> = std::sync::Mutex::new(None);

/// Set the host (`host`) or domain name of the process's UTS namespace,
/// as `sethostname` does: `EPERM` in the initial one, the Mac's.
pub fn set_current_name(host: bool, name: &[u8]) -> Result<(), i32> {
    let uts = UTS.lock().unwrap_or_else(|e| e.into_inner()).clone();
    Namespaces { uts, ..Default::default() }.set_name(host, name)
}

/// The longest host name Linux holds (`__NEW_UTS_LEN`).
pub const HOST_NAME_MAX: usize = 64;

/// The host's name, as Linux would hold it: no longer than
/// [`HOST_NAME_MAX`] (macOS allows 255), so `uname` and
/// `/proc/sys/kernel/hostname` agree.
pub fn host_name() -> Vec<u8> {
    let mut host = [0u8; 256];
    // SAFETY: `host` is a valid buffer of its length.
    if unsafe { libc::gethostname(host.as_mut_ptr().cast(), host.len()) } != 0 {
        return b"localhost".to_vec();
    }
    let end = host.iter().position(|&c| c == 0).unwrap_or(host.len()).min(HOST_NAME_MAX);
    host[..end].to_vec()
}

/// The user namespace that owns the namespace whose record is `dir`, as
/// the directory of its record (empty: the initial one, which owns every
/// initial namespace, and a record that names none). Read once per
/// process: it never changes.
pub fn owner_dir(dir: &[u8]) -> Vec<u8> {
    static OWNERS: std::sync::Mutex<Vec<(Vec<u8>, Vec<u8>)>> = std::sync::Mutex::new(Vec::new());
    let mut known = OWNERS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, o)) = known.iter().find(|(d, _)| d == dir) {
        return o.clone();
    }
    let owner = owner_of(dir).map(|(d, _)| d).unwrap_or_default();
    known.push((dir.to_vec(), owner.clone()));
    owner
}

/// The owner of namespace record `r` (`None`: an initial namespace).
fn owner_or_initial<T: Data>(r: &Option<Arc<Record<T>>>) -> Vec<u8> {
    r.as_ref().map_or_else(Vec::new, |r| owner_dir(r.dir()))
}

impl Namespaces {
    /// The directory of the user namespace's record (empty for the initial
    /// one).
    pub fn user_dir(&self) -> Vec<u8> {
        self.user.as_ref().map_or_else(Vec::new, |u| u.dir().to_vec())
    }

    /// The user namespace that owns the process's namespace of
    /// `CLONE_NEW*` type `kind` (UTS, IPC, network, cgroup or pid; the
    /// mount namespace's table names its own), as its record's directory
    /// (empty: the initial one): where a capability over what the
    /// namespace holds is asked for.
    pub fn owner(&self, kind: u64) -> Vec<u8> {
        match kind {
            CLONE_NEWUTS => owner_or_initial(&self.uts),
            CLONE_NEWIPC => owner_or_initial(&self.ipc),
            CLONE_NEWNET => owner_or_initial(&self.net),
            CLONE_NEWCGROUP => owner_or_initial(&self.cgroup),
            CLONE_NEWPID => owner_or_initial(&self.pid),
            _ => Vec::new(),
        }
    }

    /// The host name `uname` and `/proc/sys/kernel/hostname` report.
    pub fn hostname(&self) -> Vec<u8> {
        match &self.uts {
            Some(u) => u.get().hostname.clone(),
            None => host_name(),
        }
    }

    /// The NIS domain name.
    pub fn domainname(&self) -> Vec<u8> {
        match &self.uts {
            Some(u) => u.get().domainname.clone(),
            None => b"(none)".to_vec(),
        }
    }

    /// Make the new namespaces `flags` asks for (other than the mount and
    /// pid ones, which the caller makes), copying what a new one starts
    /// with from this process's.
    /// `euid` is the maker's effective uid (the initial namespace's), which
    /// owns a new user namespace.
    pub fn unshare(&mut self, flags: u64, euid: u32) -> Result<(), i32> {
        self.may_make(flags)?;
        // The user namespace first: the others are made in it.
        if flags & CLONE_NEWUSER != 0 {
            let parent = self.user.as_ref().map(|r| (r.dir().to_vec(), r.id()));
            let owner = euid;
            let ns = crate::userns::UserNs { parent, owner, ..Default::default() };
            let made = Arc::new(Record::fresh("user", ns)?);
            set_owner(made.dir(), self.user.as_deref());
            self.user = Some(made);
        }
        let user = self.user.clone();
        fn owned<T: Data>(
            r: Record<T>,
            user: &Option<Arc<Record<crate::userns::UserNs>>>,
        ) -> Arc<Record<T>> {
            set_owner(r.dir(), user.as_deref());
            Arc::new(r)
        }
        if flags & CLONE_NEWUTS != 0 {
            let uts = Uts { hostname: self.hostname(), domainname: self.domainname() };
            self.uts = Some(owned(Record::fresh("uts", uts)?, &user));
        }
        if flags & CLONE_NEWIPC != 0 {
            self.ipc = Some(owned(Record::fresh("ipc", Ipc::default())?, &user));
        }
        if flags & CLONE_NEWNET != 0 {
            self.net = Some(owned(Record::fresh("net", Net::default())?, &user));
        }
        if flags & CLONE_NEWCGROUP != 0 {
            let root = crate::cgroupfs::current();
            self.cgroup = Some(owned(Record::fresh("cgroup", Cgroup { root })?, &user));
        }
        Ok(())
    }

    /// Whether the namespaces `flags` asks for can be made (`ENOSPC` if
    /// not): a user namespace no deeper than Linux nests them (32 below
    /// the initial one's child), and of each kind fewer than its
    /// `user.max_<kind>_namespaces` sysctl allows, counting the ones fwe's
    /// processes are in. The limits are those of the initial user
    /// namespace, for every user and namespace.
    pub fn may_make(&self, flags: u64) -> Result<(), i32> {
        const KINDS: [(u64, &str); 7] = [
            (CLONE_NEWUSER, "user"),
            (CLONE_NEWNS, "mnt"),
            (CLONE_NEWUTS, "uts"),
            (CLONE_NEWIPC, "ipc"),
            (CLONE_NEWNET, "net"),
            (CLONE_NEWCGROUP, "cgroup"),
            (CLONE_NEWPID, "pid"),
        ];
        if flags & CLONE_NEWUSER != 0 && self.user_level() > 32 {
            return Err(errno::ENOSPC);
        }
        let wanted: Vec<&str> =
            KINDS.iter().filter(|(k, _)| flags & k != 0).map(|(_, n)| *n).collect();
        if wanted.is_empty() {
            return Ok(());
        }
        let mut live = std::collections::HashSet::new();
        for (_, r) in crate::procreg::all() {
            live.extend(r.ns);
            live.extend(r.held);
        }
        live.extend(self.dirs());
        // The maker's user namespaces, its own first, then the initial one
        // (`None`): a new namespace counts against each of them.
        let mut levels: Vec<Option<Vec<u8>>> = crate::userns::chain_from(self.user.clone())
            .iter()
            .map(|u| Some(u.dir().to_vec()))
            .collect();
        levels.push(None);
        for name in wanted {
            let key = format!("user/max_{name}_namespaces");
            // Each live one of the kind, by the user namespaces above it.
            let owners: Vec<Vec<Vec<u8>>> = live
                .iter()
                .filter(|d| of_kind(d, name))
                .map(|d| {
                    crate::userns::chain_from(
                        owner_of(d).and_then(|(d, id)| Record::join(&d, id).ok().map(Arc::new)),
                    )
                    .iter()
                    .map(|u| u.dir().to_vec())
                    .collect()
                })
                .collect();
            for level in &levels {
                let n = match level {
                    Some(l) => owners.iter().filter(|o| o.contains(l)).count(),
                    None => owners.len(),
                };
                if n as i64 >= crate::sysctl::user_limit(level.as_deref(), &key) {
                    return Err(errno::ENOSPC);
                }
            }
        }
        Ok(())
    }

    /// How deep the user namespace is: 0 for the initial one.
    pub fn user_level(&self) -> usize {
        let mut at = self.user.as_ref().map(|u| (u.dir().to_vec(), u.id()));
        let mut level = 0;
        while let Some((d, id)) = at {
            level += 1;
            if level > 64 {
                break;
            }
            at = Record::<crate::userns::UserNs>::join(&d, id)
                .ok()
                .and_then(|r| r.get().parent.clone());
        }
        level
    }

    /// `sethostname`/`setdomainname`: in a UTS namespace of the process's
    /// own; the host's names are not the guest's to change.
    pub fn set_name(&self, host: bool, name: &[u8]) -> Result<(), i32> {
        let Some(u) = &self.uts else { return Err(errno::EPERM) };
        u.update(|u| {
            if host {
                u.hostname = name.to_vec();
            } else {
                u.domainname = name.to_vec();
            }
            Ok(())
        })
    }

    /// What `/proc/self/ns/<kind>` links to.
    pub fn link(&self, kind: &[u8], mnt: u64) -> Option<Vec<u8>> {
        fn id<T: Data>(r: &Option<Arc<Record<T>>>, init: u64) -> u64 {
            r.as_ref().map_or(init, |r| r.id())
        }
        let n = match kind {
            b"uts" => id(&self.uts, INIT_UTS),
            b"ipc" => id(&self.ipc, INIT_IPC),
            b"net" => id(&self.net, INIT_NET),
            b"cgroup" => id(&self.cgroup, INIT_CGROUP),
            b"pid" => id(&self.pid, INIT_PID),
            b"pid_for_children" => id(&self.pid_children, INIT_PID),
            b"user" => id(&self.user, INIT_USER),
            b"mnt" => mnt,
            _ => return None,
        };
        let name: &[u8] = if kind == b"pid_for_children" { b"pid" } else { kind };
        Some([name, format!(":[{n}]").as_bytes()].concat())
    }

    /// The directories of the namespaces' shared records (none for the
    /// initial ones).
    pub fn dirs(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut add = |d: Option<&[u8]>| {
            if let Some(d) = d {
                out.push(d.to_vec());
            }
        };
        add(self.uts.as_ref().map(|r| r.dir()));
        add(self.ipc.as_ref().map(|r| r.dir()));
        add(self.net.as_ref().map(|r| r.dir()));
        add(self.cgroup.as_ref().map(|r| r.dir()));
        add(self.pid.as_ref().map(|r| r.dir()));
        add(self.pid_children.as_ref().map(|r| r.dir()));
        add(self.user.as_ref().map(|r| r.dir()));
        out
    }

    /// Make these the namespaces the process's sockets act in (see
    /// [`crate::netns`]); called whenever the process's change.
    #[cfg_attr(
        target_os = "macos",
        unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
    )]
    pub fn activate(&self) {
        crate::netns::set_current(self.net.clone());
        crate::userns::set_current(self.user.clone());
        crate::sysvipc::activate(self.ipc.clone());
        *UTS.lock().unwrap_or_else(|e| e.into_inner()) = self.uts.clone();
        crate::cgroupfs::set_ns_root(
            &self.cgroup.as_ref().map_or(b"/".to_vec(), |c| c.get().root.clone()),
        );
    }

    /// Make `own` the calling thread's own namespaces for its sockets and
    /// IPC ([`crate::threadfs`]), or the process's again (`None`). (A user
    /// namespace is never a thread's own: one with other threads cannot
    /// change it.)
    #[cfg_attr(
        target_os = "macos",
        unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
    )]
    pub fn activate_thread(own: Option<Namespaces>) {
        crate::netns::set_thread(own.as_ref().map(|n| n.net.clone()));
        crate::sysvipc::set_thread(own.map(|n| n.ipc));
    }

    /// Write the namespaces into a fork snapshot or exec state.
    pub fn save(&self, e: &mut Enc) {
        shared::save_opt(e, &self.uts);
        shared::save_opt(e, &self.ipc);
        shared::save_opt(e, &self.net);
        shared::save_opt(e, &self.cgroup);
        shared::save_opt(e, &self.pid);
        shared::save_opt(e, &self.pid_children);
        shared::save_opt(e, &self.user);
    }

    /// What [`Namespaces::save`] wrote.
    pub fn load(d: &mut Dec) -> Result<Namespaces, i32> {
        Ok(Namespaces {
            uts: shared::load_opt(d)?,
            ipc: shared::load_opt(d)?,
            net: shared::load_opt(d)?,
            cgroup: shared::load_opt(d)?,
            pid: shared::load_opt(d)?,
            pid_children: shared::load_opt(d)?,
            user: shared::load_opt(d)?,
        })
    }
}
