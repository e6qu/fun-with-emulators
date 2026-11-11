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
/// A fork under way resets the child's handlers (`CLONE_CLEAR_SIGHAND`):
/// for the state a VM child is handed ([`crate::Kernel::save_for_fork`]).
/// Set and cleared under the kernel lock.
pub(crate) static CLEAR_SIGHAND: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Whether this process was made sharing its parent's descriptor table
/// (`CLONE_FILES`, which a host fork copies), until it unshares it.
static FILES_SHARED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

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
    /// The cgroup it starts in (`CLONE_INTO_CGROUP`), if not this
    /// process's.
    cgroup: Option<Vec<u8>>,
    /// Its handlers are reset (`CLONE_CLEAR_SIGHAND`).
    clear_sighand: bool,
    /// It shares its parent's descriptor table (`CLONE_FILES`).
    files: bool,
    /// The signal its end is told with.
    exit_signal: u64,
    /// `CLONE_PIDFD`: the descriptor made ready for the child, and where it
    /// goes.
    pidfd: Option<(i32, u64)>,
}

impl<P: Platform> Kernel<P> {
    /// `unshare(flags)`.
    pub(crate) fn sys_unshare(&mut self, flags: u64) -> i64 {
        // What a single-threaded process does not share anyway.
        let unshared = CLONE_FILES | CLONE_FS | CLONE_SYSVSEM | CLONE_SIGHAND | CLONE_VM;
        if flags & !(unshared | SUPPORTED) != 0 {
            return err(errno::EINVAL);
        }
        // A descriptor table shared with another process, or with other
        // threads, is copied: past `fs.nr_open` descriptors it cannot be.
        if flags & CLONE_FILES != 0
            && (FILES_SHARED.load(std::sync::atomic::Ordering::SeqCst)
                || crate::thread::live_threads() > 1)
        {
            let nr_open = crate::sysctl::number(b"fs/nr_open").unwrap_or(1 << 20);
            let slots = crate::fdtable::open_fds().last().map_or(0, |&fd| i64::from(fd) + 1);
            if slots > nr_open {
                return err(errno::EMFILE);
            }
            FILES_SHARED.store(false, std::sync::atomic::Ordering::SeqCst);
        }
        // `CLONE_NEWNS` unshares `CLONE_FS` too: with other threads, the
        // caller's root, working directory and umask become its own.
        if flags & (CLONE_FS | CLONE_NEWNS) != 0
            && let Err(e) = self.own_view(true)
        {
            return err(e);
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
        // With other threads, the namespaces become the caller's own.
        if let Err(e) = self.own_view(false) {
            return err(e);
        }
        let fs = self.fs_mut();
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
        let fs = self.fs_mut();
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
        self.namespaces_changed();
        0
    }

    /// Before the calling thread changes its namespaces, or with `fs` its
    /// root, working directory and umask apart from the other threads'
    /// (`CLONE_FS`): with other threads it takes a view of its own
    /// ([`crate::threadfs`]).
    pub(crate) fn own_view(&mut self, fs: bool) -> Result<(), i32> {
        if crate::threadfs::current().is_some() {
            if fs {
                crate::threadfs::unshare_fs();
            }
            return Ok(());
        }
        if crate::thread::live_threads() <= 1 {
            return Ok(());
        }
        let copy = self.fs().copy()?;
        crate::threadfs::take(copy, !fs);
        Ok(())
    }

    /// After the calling thread's namespaces changed: the process's, which
    /// its record shows and its sockets act in, or the thread's own.
    pub(crate) fn namespaces_changed(&mut self) {
        match (crate::threadfs::current(), self.fs.as_ref()) {
            (Some(_), Some(process)) => crate::threadfs::namespaces_changed(process),
            _ => {
                let fs = self.fs();
                crate::procreg::own_namespaces(fs.ns_dirs());
                fs.ns.activate();
            }
        }
    }

    /// The calling thread's own view, if it has one, becomes the
    /// process's: it is the only thread left (a `fork` child), or the one
    /// that goes on to run another program.
    pub fn adopt_thread_view(&mut self) {
        if let Some(fs) = crate::threadfs::take_for_child() {
            fs.publish();
            self.fs = Some(fs);
            if let Some(fs) = self.fs.as_ref() {
                crate::procreg::own_namespaces(fs.ns_dirs());
                fs.ns.activate();
            }
        }
    }

    /// A call that may change the calling thread's root, working directory
    /// or umask: the threads that share them have them too.
    pub(crate) fn view_call(&mut self, call: impl FnOnce(&mut Self) -> i64) -> i64 {
        let r = call(self);
        if r >= 0 {
            self.share_view();
        }
        r
    }

    /// After the calling thread changed its root, working directory or
    /// umask: the threads that share them have them too.
    fn share_view(&mut self) {
        if !crate::threadfs::any() {
            return;
        }
        let Ok(from) = self.fs().copy() else { return };
        crate::threadfs::share_view(&from, self.fs.as_mut());
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
    pub fn fork_begin(&mut self, a: &crate::CloneArgs) -> Result<ForkNs, i32> {
        // The mappings the child inherits are the parent's, published.
        crate::maps::flush();
        // `CLONE_PIDFD`: the descriptor, and that it can be put where it
        // goes, before anything else is done for the child.
        let pidfd = if a.flags & CLONE_PIDFD != 0 {
            let word: i32 = crate::uaccess::read(a.pidfd).map_err(|_| errno::EFAULT)?;
            crate::uaccess::write(a.pidfd, word).map_err(|_| errno::EFAULT)?;
            Some((crate::pidfd::reserve()?, a.pidfd))
        } else {
            None
        };
        match self.fork_begin_ns(a) {
            Ok(t) => Ok(ForkNs { pidfd, ..t }),
            Err(e) => {
                if let Some((fd, _)) = pidfd {
                    // SAFETY: the descriptor made above, not yet the guest's.
                    unsafe { libc::close(fd) };
                }
                Err(e)
            }
        }
    }

    fn fork_begin_ns(&mut self, a: &crate::CloneArgs) -> Result<ForkNs, i32> {
        let flags = a.flags;
        // Limits left for this process are its own before its child
        // inherits them.
        self.take_pending_limits();
        // RLIMIT_NPROC: a user with as many processes as it allows has no
        // more but as root or with CAP_SYS_RESOURCE or CAP_SYS_ADMIN, as on
        // Linux (the host's limit, the user's on the host, applies too).
        let (nproc, _) = crate::rlimits::get(fwe_abi::resource::RLIMIT_NPROC);
        if nproc != fwe_abi::resource::RLIM_INFINITY
            && self.creds.uid != 0
            && !self.creds.has(crate::caps::CAP_SYS_RESOURCE)
            && !self.creds.has_admin()
        {
            let uid = self.creds.uid;
            let mine = crate::procreg::all().iter().filter(|(_, r)| r.ids[0] == uid).count();
            if mine as u64 >= nproc {
                return Err(errno::EAGAIN);
            }
        }
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
        // The cgroup it starts in: this process's, or with
        // `CLONE_INTO_CGROUP` the one the descriptor is of, which must be
        // a cgroup directory a process may join.
        let cgroup = match a.cgroup {
            None => None,
            Some(fd) => {
                let host = crate::fs::host_path_of(fd).ok_or(errno::EBADF)?;
                match crate::cgroupfs::locate(&host) {
                    Some((cg, None)) => {
                        crate::cgroupfs::may_join(&cg)?;
                        Some(cg)
                    }
                    _ => return Err(errno::EBADF),
                }
            }
        };
        // Within the cgroup's `pids.max`.
        crate::cgroupfs::fork_allowed(&cgroup.clone().unwrap_or_else(crate::cgroupfs::current))?;
        CLEAR_SIGHAND.store(
            flags & fwe_abi::clone::CLONE_CLEAR_SIGHAND != 0,
            std::sync::atomic::Ordering::SeqCst,
        );
        let fs = self.fs_mut();
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
        let clear_sighand = flags & fwe_abi::clone::CLONE_CLEAR_SIGHAND != 0;
        let exit_signal = flags & fwe_abi::clone::CSIGNAL;
        Ok(ForkNs {
            saved,
            chain,
            nums,
            dirs,
            caps,
            line,
            inherit,
            cgroup,
            clear_sighand,
            files: flags & fwe_abi::clone::CLONE_FILES != 0,
            exit_signal,
            pidfd: None,
        })
    }

    /// In the parent after the host `fork` (`child` is the child's host
    /// pid, or negative if it failed): back to its own namespaces. Returns
    /// the child's pid as the parent sees it.
    pub fn fork_parent(&mut self, t: ForkNs, child: i32) -> i32 {
        CLEAR_SIGHAND.store(false, std::sync::atomic::Ordering::SeqCst);
        if let Some(caps) = t.caps {
            self.creds.caps = caps;
        }
        if let Some((mnt, ns)) = t.saved {
            let fs = self.fs_mut();
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
                t.cgroup.as_deref(),
            );
            // It holds this process's session keyring.
            crate::keys::forked(child);
            crate::reaper::set_exit_signal(child, t.exit_signal);
            if let Some((fd, at)) = t.pidfd {
                crate::pidfd::attach(fd, child);
                let _ = crate::uaccess::write(at, fd);
            }
        } else if let Some((fd, _)) = t.pidfd {
            // SAFETY: the descriptor made for the child there is none of.
            unsafe { libc::close(fd) };
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
        // Its view is the forking thread's.
        self.adopt_thread_view();
        // Its numbers stand for it from now on, not only once the parent
        // gets to it: whether it is an init, for one, depends on it.
        // SAFETY: getpid cannot fail.
        pidns::set_host(&t.chain, &t.nums, unsafe { libc::getpid() });
        pidns::set_current(t.chain);
        if let Some(fs) = self.fs_opt() {
            fs.ns.activate();
        }
        // Its own record too: it may end before the parent writes it.
        // With the mappings it inherited, for other processes'
        // `/proc/<pid>/maps`.
        let auxv = self.fs_opt().map(|fs| fs.auxv().to_vec()).unwrap_or_default();
        crate::procreg::own_line(&t.line, &t.inherit, t.dirs.clone(), crate::maps::forked(), &auxv);
        if let Some(cg) = &t.cgroup {
            // Where it starts, should it look before the parent writes it.
            // SAFETY: getpid cannot fail.
            let _ = crate::procreg::set_cgroup(unsafe { libc::getpid() }, cg);
        }
        if t.clear_sighand {
            self.clear_handlers();
        }
        FILES_SHARED.store(t.files, std::sync::atomic::Ordering::SeqCst);
        CLEAR_SIGHAND.store(false, std::sync::atomic::Ordering::SeqCst);
        crate::reaper::forked_child();
        crate::fs::forked_child_fifos();
        crate::reaper::start_if_reaper();
        // SAFETY: getpid cannot fail.
        t.nums.first().copied().unwrap_or_else(|| unsafe { libc::getpid() })
    }

    /// `CLONE_CLEAR_SIGHAND`: every handler back to the default action (an
    /// ignored signal stays ignored), with no flags or mask, as Linux
    /// resets them.
    pub(crate) fn clear_handlers(&mut self) {
        for a in &mut self.sigactions {
            if a.handler != fwe_abi::signal::SIG_IGN {
                a.handler = fwe_abi::signal::SIG_DFL;
            }
            a.flags = 0;
            a.mask = 0;
        }
        self.sync_all_host_signals();
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
