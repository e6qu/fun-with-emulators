//! `unshare`, `sethostname` and `setdomainname`, and the namespaces a
//! `clone` makes for its child ([`ForkNs`]).

use crate::ns::Namespaces;
use crate::pidns::{self, PidNs};
use crate::shared::Record;
use crate::{Kernel, Platform, guest, uaccess};
use fwe_abi::clone::*;
use fwe_abi::{err, errno};
use std::sync::Arc;

/// The namespaces fwe can make.
const SUPPORTED: u64 = CLONE_NEWNS
    | CLONE_NEWUTS
    | CLONE_NEWIPC
    | CLONE_NEWNET
    | CLONE_NEWCGROUP
    | CLONE_NEWPID
    | CLONE_NEWUSER;

/// The capabilities a process has in a user namespace it has just made:
/// all of them, as Linux gives them.
fn caps_in_new_userns() -> crate::caps::Caps {
    crate::caps::Caps {
        effective: crate::caps::ALL,
        permitted: crate::caps::ALL,
        inheritable: 0,
        bounding: crate::caps::ALL,
        ambient: 0,
        securebits: 0,
    }
}

/// What a `clone` that makes a process arranges for the child's
/// namespaces, from before the host `fork` until it is known how it went
/// ([`Kernel::fork_parent`], [`Kernel::fork_child`]).
pub struct ForkNs {
    /// The parent's own, while it has the child's for the fork.
    saved: Option<(Arc<crate::mounts::store::Ns>, Namespaces)>,
    /// The child's namespaces' records, for its record.
    dirs: Vec<Vec<u8>>,
    /// The parent's capabilities, while the child's (in a new user
    /// namespace) are in place for the fork.
    caps: Option<crate::caps::Caps>,
    /// The child's pid namespaces, and its numbers in them.
    chain: pidns::Chain,
    nums: Vec<i32>,
    /// The child's line of ancestors and the bound of its adoption (see
    /// [`crate::reaper`]).
    line: (Vec<crate::procreg::Proc>, Option<crate::procreg::Proc>),
    /// What the child inherits of this process's record.
    inherit: crate::procreg::Inherit,
}

impl<P: Platform> Kernel<P> {
    /// `unshare(flags)`.
    pub(crate) fn sys_unshare(&mut self, flags: u64) -> i64 {
        // What a single-threaded process does not share anyway.
        let unshared = CLONE_FILES | CLONE_FS | CLONE_SYSVSEM | CLONE_SIGHAND | CLONE_VM;
        if flags & !(unshared | SUPPORTED) != 0 {
            return err(errno::EINVAL);
        }
        if flags & SUPPORTED == 0 {
            return 0;
        }
        // A new user namespace needs no privilege, and gives the caller what
        // the others need; it cannot be made by a process with other threads.
        let new_user = flags & CLONE_NEWUSER != 0;
        if new_user && crate::thread::live_threads() > 1 {
            return err(errno::EINVAL);
        }
        if !new_user && !self.creds.has_admin() {
            return err(errno::EPERM);
        }
        let fs = self.fs.as_mut().expect("filesystem configured");
        if let Err(e) = fs.ns.unshare(flags) {
            return err(e);
        }
        // Owned by the user namespace it is made in, a new one included.
        if flags & CLONE_NEWNS != 0 {
            match fs.mount_ns().copy(&fs.ns.user_dir()) {
                Ok(copy) => fs.set_mount_ns(Arc::new(copy)),
                Err(e) => return err(e),
            }
        }
        if new_user {
            self.creds.caps = caps_in_new_userns();
        }
        let fs = self.fs.as_mut().expect("filesystem configured");
        if flags & CLONE_NEWPID != 0 {
            // A second one before a child was made in the first fails.
            let unshared = match (&fs.ns.pid, &fs.ns.pid_children) {
                (None, None) => false,
                (Some(a), Some(b)) => a.dir() != b.dir(),
                _ => true,
            };
            if unshared {
                return err(errno::EINVAL);
            }
            // For the children: the process itself stays where it is.
            let parent = fs.ns.pid_children.as_ref().map(|r| (r.dir().to_vec(), r.id()));
            match Record::fresh("pid", PidNs::new(parent)) {
                Ok(r) => fs.ns.pid_children = Some(Arc::new(r)),
                Err(e) => return err(e),
            }
        }
        crate::procreg::own_namespaces(fs.ns_dirs());
        fs.ns.activate();
        0
    }

    /// `sethostname(name, len)`, or `setdomainname` when `!host`.
    pub(crate) fn sys_setname(&mut self, name: u64, len: u64, host: bool) -> i64 {
        if !self.creds.has_admin() {
            return err(errno::EPERM);
        }
        if len > 64 {
            return err(errno::EINVAL);
        }
        let mut buf = vec![0u8; len as usize];
        guest!(uaccess::read_into(name, &mut buf));
        match self.fs().ns.set_name(host, &buf) {
            Ok(()) => 0,
            Err(e) => err(e),
        }
    }

    /// Before the host `fork` of a `clone` with `flags`: make the
    /// namespaces the child is to have, number it in its pid namespaces,
    /// and give the parent the child's view for the fork, so that the child
    /// inherits it. The caller holds the kernel lock until
    /// [`Kernel::fork_parent`] or [`Kernel::fork_child`].
    pub fn fork_begin(&mut self, flags: u64) -> Result<ForkNs, i32> {
        // Limits left for this process are its own before its child
        // inherits them.
        self.take_pending_limits();
        // And so are its keyrings.
        crate::keys::before_fork();
        if flags & CLONE_NEWTIME != 0 {
            return Err(errno::EINVAL);
        }
        let new = flags & SUPPORTED;
        let new_user = new & CLONE_NEWUSER != 0;
        if new != 0 && !new_user && !self.creds.has_admin() {
            return Err(errno::EPERM);
        }
        // Taken while this process's own pid namespaces are current.
        let mut line = crate::procreg::child_line();
        if flags & fwe_abi::clone::CLONE_PARENT != 0
            && crate::pidns::current().first().is_some_and(|ns| {
                // SAFETY: getpid cannot fail.
                ns.get().number_of(unsafe { libc::getpid() }) == Some(1)
            })
        {
            // A pid namespace's init has no parent in its namespace to give.
            return Err(errno::EINVAL);
        }
        if flags & fwe_abi::clone::CLONE_PARENT != 0 && !line.0.is_empty() {
            // Its parent is this process's parent, as Linux has it (the
            // host's is this process, which the host cannot change).
            line.0.remove(0);
        }
        // Within the cgroup's `pids.max`.
        crate::cgroupfs::fork_allowed(&crate::cgroupfs::current())?;
        let fs = self.fs.as_mut().expect("filesystem configured");
        let mut ns = fs.ns.clone();
        ns.unshare(new)?;
        let base = fs.ns.pid_children.clone();
        let child_pid_ns = if new & CLONE_NEWPID != 0 {
            let parent = base.as_ref().map(|r| (r.dir().to_vec(), r.id()));
            Some(Arc::new(Record::fresh("pid", PidNs::new(parent))?))
        } else {
            base
        };
        ns.pid = child_pid_ns.clone();
        ns.pid_children = child_pid_ns.clone();
        let mnt = if new & CLONE_NEWNS != 0 {
            Some(Arc::new(fs.mount_ns().copy(&ns.user_dir())?))
        } else {
            None
        };
        // Numbered last, so that nothing after it can fail and leave the
        // numbers taken.
        let chain = pidns::chain_from(child_pid_ns);
        let nums = if chain.is_empty() { Vec::new() } else { pidns::alloc(&chain, 0, false)? };
        let saved = if new != 0 || !nums.is_empty() {
            let old = (fs.mount_ns().clone(), std::mem::replace(&mut fs.ns, ns));
            if let Some(m) = mnt {
                fs.set_mount_ns(m);
            }
            Some(old)
        } else {
            None
        };
        let dirs = fs.ns_dirs();
        let caps = new_user.then(|| std::mem::replace(&mut self.creds.caps, caps_in_new_userns()));
        let inherit = crate::procreg::inherit();
        Ok(ForkNs { saved, chain, nums, dirs, caps, line, inherit })
    }

    /// In the parent after the host `fork` (`child` is the child's host
    /// pid, or negative if it failed): back to its own namespaces. Returns
    /// the child's pid as the parent sees it.
    pub fn fork_parent(&mut self, t: ForkNs, child: i32) -> i32 {
        if let Some(caps) = t.caps {
            self.creds.caps = caps;
        }
        if let Some((mnt, ns)) = t.saved {
            let fs = self.fs.as_mut().expect("filesystem configured");
            fs.set_mount_ns(mnt);
            fs.ns = ns;
        }
        if child > 0 {
            // It starts in this process's cgroup, in its namespaces.
            crate::procreg::forked(
                child,
                t.dirs.clone(),
                &t.line,
                &t.inherit,
                crate::maps::snapshot(),
            );
            // It holds this process's session keyring.
            crate::keys::forked(child);
        }
        if child <= 0 {
            for (r, n) in t.chain.iter().zip(&t.nums) {
                let _ = r.update(|ns| {
                    ns.pids.remove(n);
                    Ok(())
                });
            }
            return child;
        }
        pidns::set_host(&t.chain, &t.nums, child);
        if t.nums.first() == Some(&1)
            && let Some(ns) = t.chain.first()
        {
            // The init of a namespace: it takes the namespace with it.
            crate::reaper::init_child(child, ns.dir().to_vec());
        }
        pidns::to_guest(child)
    }

    /// In the child after the host `fork`: its pid namespaces are the ones
    /// made for it. Returns its pid, for `thread::init_main`.
    pub fn fork_child(&mut self, t: ForkNs) -> i32 {
        // Its numbers stand for it from now on, not only once the parent
        // gets to it: whether it is an init, for one, depends on it.
        // SAFETY: getpid cannot fail.
        pidns::set_host(&t.chain, &t.nums, unsafe { libc::getpid() });
        pidns::set_current(t.chain);
        if let Some(fs) = self.fs.as_ref() {
            fs.ns.activate();
        }
        // Its own record too: it may end before the parent writes it.
        // With the mappings it inherited, for other processes'
        // `/proc/<pid>/maps`.
        crate::procreg::own_line(&t.line, &t.inherit, crate::maps::forked());
        crate::reaper::forked_child();
        crate::fs::forked_child_fifos();
        crate::reaper::start_if_reaper();
        // SAFETY: getpid cannot fail.
        t.nums.first().copied().unwrap_or_else(|| unsafe { libc::getpid() })
    }

    /// The child's pid in its own pid namespace, once [`Kernel::fork_begin`]
    /// numbered it there (0 in the initial one).
    pub fn fork_number(t: &ForkNs) -> i32 {
        t.nums.first().copied().unwrap_or(0)
    }

    /// The child's line of ancestors and bound, for a child that starts
    /// on state the parent hands it (a VM fork's).
    pub fn fork_line(t: &ForkNs) -> &(Vec<crate::procreg::Proc>, Option<crate::procreg::Proc>) {
        &t.line
    }

    /// What the child inherits of this process's record, likewise.
    pub fn fork_inherit(t: &ForkNs) -> &crate::procreg::Inherit {
        &t.inherit
    }
}
