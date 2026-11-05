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
const SUPPORTED: u64 =
    CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWCGROUP | CLONE_NEWPID;

/// What a `clone` that makes a process arranges for the child's
/// namespaces, from before the host `fork` until it is known how it went
/// ([`Kernel::fork_parent`], [`Kernel::fork_child`]).
pub struct ForkNs {
    /// The parent's own, while it has the child's for the fork.
    saved: Option<(Arc<crate::mounts::store::Ns>, Namespaces)>,
    /// The child's namespaces' records, for its record.
    dirs: Vec<Vec<u8>>,
    /// The child's pid namespaces, and its numbers in them.
    chain: pidns::Chain,
    nums: Vec<i32>,
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
        if !self.creds.has_admin() {
            return err(errno::EPERM);
        }
        let fs = self.fs.as_mut().expect("filesystem configured");
        if flags & CLONE_NEWNS != 0 {
            match fs.mount_ns().copy() {
                Ok(copy) => fs.set_mount_ns(Arc::new(copy)),
                Err(e) => return err(e),
            }
        }
        if let Err(e) = fs.ns.unshare(flags) {
            return err(e);
        }
        if flags & CLONE_NEWPID != 0 {
            // For the children: the process itself stays where it is.
            let parent = fs.ns.pid_children.as_ref().map(|r| (r.dir().to_vec(), r.id()));
            match Record::fresh("pid", PidNs::new(parent)) {
                Ok(r) => fs.ns.pid_children = Some(Arc::new(r)),
                Err(e) => return err(e),
            }
        }
        crate::procreg::own_namespaces(fs.ns_dirs());
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
        if flags & CLONE_NEWUSER != 0 || flags & CLONE_NEWTIME != 0 {
            return Err(errno::EINVAL);
        }
        let new = flags & SUPPORTED;
        if new != 0 && !self.creds.has_admin() {
            return Err(errno::EPERM);
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
        let chain = pidns::chain_from(child_pid_ns);
        let nums = if chain.is_empty() { Vec::new() } else { pidns::alloc(&chain, 0, false)? };
        let mnt = if new & CLONE_NEWNS != 0 { Some(Arc::new(fs.mount_ns().copy()?)) } else { None };
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
        Ok(ForkNs { saved, chain, nums, dirs })
    }

    /// In the parent after the host `fork` (`child` is the child's host
    /// pid, or negative if it failed): back to its own namespaces. Returns
    /// the child's pid as the parent sees it.
    pub fn fork_parent(&mut self, t: ForkNs, child: i32) -> i32 {
        if let Some((mnt, ns)) = t.saved {
            let fs = self.fs.as_mut().expect("filesystem configured");
            fs.set_mount_ns(mnt);
            fs.ns = ns;
        }
        if child > 0 {
            // It starts in this process's cgroup, in its namespaces.
            crate::procreg::forked(child, t.dirs.clone());
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
        pidns::to_guest(child)
    }

    /// In the child after the host `fork`: its pid namespaces are the ones
    /// made for it. Returns its pid, for `thread::init_main`.
    pub fn fork_child(&mut self, t: ForkNs) -> i32 {
        pidns::set_current(t.chain);
        // SAFETY: getpid cannot fail.
        t.nums.first().copied().unwrap_or_else(|| unsafe { libc::getpid() })
    }

    /// The child's pid in its own pid namespace, once [`Kernel::fork_begin`]
    /// numbered it there (0 in the initial one).
    pub fn fork_number(t: &ForkNs) -> i32 {
        t.nums.first().copied().unwrap_or(0)
    }
}
