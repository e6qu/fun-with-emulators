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

/// An IPC namespace: its identity (fwe has no System V IPC objects, and
/// POSIX message queues are the mqueue filesystem's).
#[derive(Clone, Default, Debug)]
pub struct Ipc;

impl Data for Ipc {
    fn encode(&self, e: &mut Enc) {
        e.u8(1);
    }
    fn decode(d: &mut Dec) -> Self {
        d.u8();
        Ipc
    }
}

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
    }
    fn decode(d: &mut Dec) -> Self {
        let lo_up = d.bool();
        let n = d.count(9);
        let ports = (0..n).map(|_| ((d.u8(), d.u32() as u16), d.u32() as u16)).collect();
        let n = d.count(16);
        let text = |d: &mut Dec| String::from_utf8_lossy(&d.bytes()).into_owned();
        let sysctls = (0..n).map(|_| (text(d), text(d))).collect();
        Net { lo_up, ports, sysctls }
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

impl Namespaces {
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
    pub fn unshare(&mut self, flags: u64) -> Result<(), i32> {
        // The user namespace first: the others are made in it.
        if flags & CLONE_NEWUSER != 0 {
            let parent = self.user.as_ref().map(|r| (r.dir().to_vec(), r.id()));
            let owner = crate::userns::from_ns(0, false).unwrap_or(0);
            let ns = crate::userns::UserNs { parent, owner, ..Default::default() };
            self.user = Some(Arc::new(Record::fresh("user", ns)?));
        }
        if flags & CLONE_NEWUTS != 0 {
            let uts = Uts { hostname: self.hostname(), domainname: self.domainname() };
            self.uts = Some(Arc::new(Record::fresh("uts", uts)?));
        }
        if flags & CLONE_NEWIPC != 0 {
            self.ipc = Some(Arc::new(Record::fresh("ipc", Ipc)?));
        }
        if flags & CLONE_NEWNET != 0 {
            self.net = Some(Arc::new(Record::fresh("net", Net::default())?));
        }
        if flags & CLONE_NEWCGROUP != 0 {
            let root = crate::cgroupfs::current();
            self.cgroup = Some(Arc::new(Record::fresh("cgroup", Cgroup { root })?));
        }
        Ok(())
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
    pub fn activate(&self) {
        crate::netns::set_current(self.net.clone());
        crate::userns::set_current(self.user.clone());
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
