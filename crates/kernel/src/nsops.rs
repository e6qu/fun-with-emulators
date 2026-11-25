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
    /// It starts in a frozen cgroup: it stops itself before it runs.
    frozen: bool,
    /// It shares its parent's descriptor table (`CLONE_FILES`).
    files: bool,
    /// It shares its parent's root, working directory and umask
    /// (`CLONE_FS`, [`crate::fsshare`]).
    fs: bool,
    /// The signal its end is told with.
    exit_signal: u64,
    /// `CLONE_PIDFD`: the descriptor made ready for the child, and where it
    /// goes.
    pidfd: Option<(i32, u64)>,
    /// What the parent alone would know of the child's record, for a child
    /// that writes its whole record itself ([`Kernel::fork_child_writes`]).
    child_writes: Option<crate::procreg::FromParent>,
    /// For such a child: its record and its view as other processes see
    /// it ([`crate::fs::Fs::shared`]), made before the fork (see
    /// [`crate::procreg::Prepared`]); none while a thread has a view of its
    /// own, which the child can take.
    prepared: Option<(crate::procreg::Prepared, Option<Vec<u8>>)>,
    /// The parent wrote that record and view for the child, with the
    /// child's start time, before letting it go on
    /// ([`Kernel::fork_write_child`]): the child writes neither.
    written: std::cell::Cell<bool>,
}

impl ForkNs {
    /// In the child: whether its parent wrote its record and view for it
    /// ([`Kernel::fork_write_child`]), as the parent told it.
    pub fn set_written(&self, written: bool) {
        self.written.set(written);
    }
}

impl<P: Platform> Kernel<P> {
    /// `unshare(flags)`.
    pub(crate) fn sys_unshare(&mut self, flags: u64) -> i64 {
        // What a single-threaded process does not share anyway.
        let unshared =
            CLONE_FILES | CLONE_FS | CLONE_SYSVSEM | CLONE_SIGHAND | CLONE_VM | CLONE_THREAD;
        if flags & !(unshared | SUPPORTED) != 0 {
            return err(errno::EINVAL);
        }
        // Its threads, signal handlers and memory are another thread's too
        // while it has other threads: they cannot be made its own. (A
        // process shares memory with no other process past a `vfork`,
        // whose parent waits.)
        if flags & (CLONE_THREAD | CLONE_SIGHAND | CLONE_VM) != 0
            && crate::thread::live_threads() > 1
        {
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
        // Alone in the process, they stop being another process's
        // (`CLONE_FS`), once the call succeeds: `CLONE_NEWUSER` unshares
        // them too.
        let leaves_fs = flags & (CLONE_FS | CLONE_NEWNS | CLONE_NEWUSER) != 0
            && crate::threadfs::current().is_none()
            && crate::thread::live_threads() <= 1;
        if flags & SUPPORTED == 0 {
            if leaves_fs {
                crate::fsshare::leave();
            }
            return 0;
        }
        // A new user namespace needs no privilege, and gives the caller what
        // the others need; it cannot be made by a process with other threads.
        let new_user = flags & CLONE_NEWUSER != 0;
        if new_user && crate::thread::live_threads() > 1 {
            return err(errno::EINVAL);
        }
        if new_user && let Err(e) = crate::userns::may_make(self.fs().proc_root() != b"/") {
            return err(e);
        }
        // The others need CAP_SYS_ADMIN in the caller's user namespace
        // (which a new one gives it), and are owned by that namespace.
        if !new_user && !self.creds.has_own(crate::caps::CAP_SYS_ADMIN) {
            return err(errno::EPERM);
        }
        // With other threads, the namespaces become the caller's own.
        if let Err(e) = self.own_view(false) {
            return err(e);
        }
        let euid = self.creds.euid;
        let fs = self.fs_mut();
        if let Err(e) = fs.ns.unshare(flags, euid) {
            return err(e);
        }
        // Owned by the user namespace it is made in, a new one included.
        if flags & CLONE_NEWNS != 0 {
            match fs.mount_ns().copy(&fs.ns.user_dir()) {
                Ok(copy) => {
                    crate::ns::set_owner(copy.dir(), fs.ns.user.as_deref());
                    fs.set_mount_ns(Arc::new(copy))
                }
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
                Ok(r) => {
                    crate::ns::set_owner(r.dir(), fs.ns.user.as_deref());
                    fs.ns.pid_children = Some(Arc::new(r))
                }
                Err(e) => return err(e),
            }
        }
        if leaves_fs {
            crate::fsshare::leave();
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
    #[cfg_attr(
        target_os = "macos",
        unsafe(link_section = "__TEXT,__fwe_fork,regular,pure_instructions")
    )]
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

    /// A call that can change the calling thread's root, working directory
    /// or umask: the threads that share them have them too.
    pub(crate) fn view_call(&mut self, call: impl FnOnce(&mut Self) -> i64) -> i64 {
        let r = call(self);
        if r >= 0 {
            self.share_view();
        }
        r
    }

    /// After the calling thread changed its root, working directory or
    /// umask: the threads, and the processes, that share them have them
    /// too.
    fn share_view(&mut self) {
        if crate::threadfs::any()
            && let Ok(from) = self.fs().copy()
        {
            crate::threadfs::share_view(&from, self.fs.as_mut());
        }
        // A thread with a view of its own that it unshared changed only
        // its own.
        if crate::fsshare::active()
            && (crate::threadfs::current().is_none() || crate::threadfs::shares())
            && let Some(fs) = self.fs.as_ref()
        {
            crate::fsshare::changed(fs.shared_view());
        }
    }

    /// As a call starts: the root, working directory and umask another
    /// process that shares them changed them to, in the process's view
    /// and the views of its threads that share it.
    pub(crate) fn take_shared_view(&mut self) {
        let Some(v) = crate::fsshare::take() else { return };
        let Some(fs) = self.fs.as_mut() else { return };
        fs.set_shared_view(&v);
        crate::threadfs::process_view_changed(&v);
    }

    /// `sethostname(name, len)`, or `setdomainname` when `!host`.
    pub(crate) fn sys_setname(&mut self, name: u64, len: u64, host: bool) -> i64 {
        // CAP_SYS_ADMIN over the UTS namespace: in the user namespace that
        // owns it.
        if !self.creds.has_in(&self.fs().ns.owner(CLONE_NEWUTS), crate::caps::CAP_SYS_ADMIN) {
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
        // RLIMIT_NPROC: a user with as many tasks (threads, in all its
        // processes) as it allows has no more but as root or with
        // CAP_SYS_RESOURCE or CAP_SYS_ADMIN, as on Linux (the host's limit,
        // the user's on the host, applies too).
        let (nproc, _) = crate::rlimits::get(fwe_abi::resource::RLIMIT_NPROC);
        if nproc != fwe_abi::resource::RLIM_INFINITY
            && self.creds.uid != 0
            && !self.creds.has(crate::caps::CAP_SYS_RESOURCE)
            && !self.creds.has(crate::caps::CAP_SYS_ADMIN)
            && crate::cgroupfs::user_tasks(self.creds.uid) >= nproc
        {
            return Err(errno::EAGAIN);
        }
        // And so are its keyrings.
        crate::keys::before_fork();
        if flags & CLONE_NEWTIME != 0 {
            return Err(errno::EINVAL);
        }
        let new = flags & SUPPORTED;
        let new_user = new & CLONE_NEWUSER != 0;
        if new_user {
            crate::userns::may_make(self.fs().proc_root() != b"/")?;
        }
        if new != 0 && !new_user && !self.creds.has_own(crate::caps::CAP_SYS_ADMIN) {
            return Err(errno::EPERM);
        }
        // Taken while this process's own pid namespaces are current.
        let mut line = crate::procreg::child_line();
        if flags & fwe_abi::clone::CLONE_PARENT != 0
            && crate::pidns::current()
                .first()
                .is_some_and(|ns| ns.get().number_of(crate::host::pid().get()) == Some(1))
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
        // `CLONE_INTO_CGROUP` the one the descriptor is of, which needs to be
        // a cgroup directory a process can join.
        let cgroup = match a.cgroup {
            None => None,
            Some(fd) => {
                let cg = crate::cgroupfs::of_fd(fd).map_err(|_| errno::EBADF)?;
                crate::cgroupfs::may_move(&crate::cgroupfs::current(), &cg)?;
                crate::cgroupfs::may_join(&cg)?;
                Some(cg)
            }
        };
        // Within the cgroup's `pids.max`; frozen with it.
        let frozen = crate::cgroupfs::fork_checks(cgroup.as_deref())?;
        CLEAR_SIGHAND.store(
            flags & fwe_abi::clone::CLONE_CLEAR_SIGHAND != 0,
            std::sync::atomic::Ordering::SeqCst,
        );
        let euid = self.creds.euid;
        // `CAP_CHECKPOINT_RESTORE` (the last) or `CAP_SYS_ADMIN`, for
        // `set_tid`, in the user namespace owning the pid namespace the
        // number is chosen in.
        let pid_owner = self
            .fs()
            .ns
            .pid_children
            .as_ref()
            .map_or_else(Vec::new, |r| crate::ns::owner_dir(r.dir()));
        let restorer = self.creds.has_in(&pid_owner, crate::caps::CAP_LAST_CAP)
            || self.creds.has_in(&pid_owner, crate::caps::CAP_SYS_ADMIN);
        let fs = self.fs_mut();
        let mut ns = fs.ns.clone();
        ns.unshare(new, euid)?;
        let base = fs.ns.pid_children.clone();
        let child_pid_ns = if new & CLONE_NEWPID != 0 {
            let parent = base.as_ref().map(|r| (r.dir().to_vec(), r.id()));
            let r = Record::fresh("pid", PidNs::new(parent))?;
            crate::ns::set_owner(r.dir(), ns.user.as_deref());
            Some(Arc::new(r))
        } else {
            base
        };
        ns.pid = child_pid_ns.clone();
        ns.pid_children = child_pid_ns.clone();
        let mnt = if new & CLONE_NEWNS != 0 {
            let copy = fs.mount_ns().copy(&ns.user_dir())?;
            crate::ns::set_owner(copy.dir(), ns.user.as_deref());
            Some(Arc::new(copy))
        } else {
            None
        };
        // Numbered last, so that nothing after it can fail and leave the
        // numbers taken.
        let chain = pidns::chain_from(child_pid_ns);
        // `set_tid`: the child's numbers chosen, in fwe's namespaces (the
        // host's own numbers are not fwe's to choose: `EPERM`), with
        // `CAP_CHECKPOINT_RESTORE` or `CAP_SYS_ADMIN`.
        let chosen = &a.set_tid[..a.set_tid_size];
        if !chosen.is_empty() {
            if chosen.len() > chain.len() + 1 {
                return Err(errno::EINVAL);
            }
            if chosen.len() > chain.len() || !restorer {
                return Err(errno::EPERM);
            }
        }
        let nums = if chain.is_empty() {
            Vec::new()
        } else {
            pidns::alloc_chosen(&chain, 0, None, chosen)?
        };
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
        let mut inherit = crate::procreg::inherit();
        // Its security state: this process's, with its own capabilities,
        // and no tracer named for it.
        inherit.sec = crate::procreg::Security { ptracer: 0, ..self.security() };
        // Its parent is this process's, not this one (a foster child).
        inherit.foster = flags & fwe_abi::clone::CLONE_PARENT != 0;
        let clear_sighand = flags & fwe_abi::clone::CLONE_CLEAR_SIGHAND != 0;
        let exit_signal = flags & fwe_abi::clone::CSIGNAL;
        // `CLONE_FS`: the record the child shares the view through. The
        // view of a thread that unshared it is that thread's alone, and the
        // child's a copy of it.
        let shares_fs = flags & CLONE_FS != 0
            && (crate::threadfs::current().is_none() || crate::threadfs::shares());
        if shares_fs {
            crate::fsshare::for_fork(self.fs().shared_view())?;
        }
        crate::fsshare::fork_shares(shares_fs);
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
            frozen,
            files: flags & fwe_abi::clone::CLONE_FILES != 0,
            fs: shares_fs,
            exit_signal,
            pidfd: None,
            child_writes: None,
            prepared: None,
            written: std::cell::Cell::new(false),
        })
    }

    /// For a fork whose child runs [`Kernel::fork_child`]: the child writes
    /// its whole record as it starts, with what this process knows of it,
    /// and this process writes none (a look at the child's record waits
    /// for it, [`crate::procreg::read`]). The record, and the view the
    /// child shows, are made here, before the fork, for the child to write
    /// as they are ([`crate::procreg::Prepared`]).
    pub fn fork_child_writes(&self, t: &mut ForkNs) {
        let from = crate::procreg::FromParent::of(t.cgroup.as_deref());
        // The forking thread's own view, which the child takes, is made
        // into the child's view and record only once it has it.
        if !crate::threadfs::any() {
            let auxv = self.fs_opt().map(|fs| fs.auxv().to_vec()).unwrap_or_default();
            let record = crate::procreg::Prepared::of(
                &t.line,
                &t.inherit,
                t.dirs.clone(),
                crate::maps::forked(),
                &auxv,
                &from,
                crate::syscalls::own_limits(),
            );
            t.prepared = Some((record, self.fs_opt().map(|fs| fs.shared())));
        }
        t.child_writes = Some(from);
    }

    /// In the parent, the host `fork` made `child`, which waits to be let
    /// go on: its record and view, prepared before the fork, written for
    /// it with its start time, so the child, whose every page touched is a
    /// fault, writes neither. Whether they were (the child is told).
    pub fn fork_write_child(&self, t: &ForkNs, child: i32) -> bool {
        let Some(child) = crate::ids::HostPid::new(child) else { return false };
        let Some((record, view)) = t.prepared.as_ref() else { return false };
        if !crate::procreg::prepared_for(child, record) {
            return false;
        }
        if let Some(view) = view {
            crate::procstore::put_for(crate::procstore::Kind::View, child, view);
        }
        t.written.set(true);
        true
    }

    /// In the parent after the host `fork` (`child` is the child's host
    /// pid, or negative if it failed): back to its own namespaces. Returns
    /// the child's pid as the parent sees it.
    pub fn fork_parent(&mut self, t: ForkNs, child: i32) -> i32 {
        CLEAR_SIGHAND.store(false, std::sync::atomic::Ordering::SeqCst);
        crate::fsshare::fork_shares(false);
        if let Some(caps) = t.caps {
            self.creds.caps = caps;
        }
        if let Some((mnt, ns)) = t.saved {
            let fs = self.fs_mut();
            fs.set_mount_ns(mnt);
            fs.ns = ns;
        }
        let forked = crate::ids::HostPid::new(child);
        if let Some(c) = forked {
            crate::mqueue::forked(c);
            crate::filestore::desc::forked(c);
        }
        if let Some(c) = forked.filter(|_| t.child_writes.is_none()) {
            // It starts in this process's cgroup, in its namespaces.
            crate::procreg::forked(
                c,
                t.dirs.clone(),
                &t.line,
                &t.inherit,
                crate::maps::snapshot(),
                t.cgroup.as_deref(),
            );
            // It holds this process's session keyring.
        }
        if let Some(c) = forked.filter(|_| t.child_writes.is_some() && !t.written.get()) {
            crate::procreg::child_writes_own(c);
        }
        if child > 0 {
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
        // Its view is the forking thread's, which other processes see.
        self.adopt_thread_view();
        let written = t.written.get();
        match t.prepared.as_ref().map(|p| &p.1) {
            Some(Some(_)) if written => {}
            Some(Some(view)) => {
                crate::procstore::put_own(crate::procstore::Kind::View, Some(view));
            }
            _ => {
                if let Some(fs) = self.fs_opt() {
                    fs.share();
                }
            }
        }
        // Its numbers stand for it from now on, not only once the parent
        // gets to it: whether it is an init, for one, depends on it.
        pidns::set_host(&t.chain, &t.nums, crate::host::pid().get());
        pidns::set_current(t.chain);
        if let Some(fs) = self.fs_opt() {
            fs.ns.activate();
        }
        // Its own record too: it might end before the parent writes it.
        // With the mappings it inherited, for other processes'
        // `/proc/<pid>/maps`.
        let prepared =
            written || t.prepared.as_ref().is_some_and(|p| crate::procreg::own_prepared(&p.0));
        let auxv = || self.fs_opt().map(|fs| fs.auxv().to_vec()).unwrap_or_default();
        match &t.child_writes {
            _ if prepared => {}
            Some(from) => crate::procreg::own_whole(
                &t.line,
                &t.inherit,
                t.dirs.clone(),
                crate::maps::forked(),
                &auxv(),
                from,
            ),
            None => crate::procreg::own_line(
                &t.line,
                &t.inherit,
                t.dirs.clone(),
                crate::maps::forked(),
                &auxv(),
            ),
        }
        // Its limits, its parent's, for other processes to read (in the
        // record prepared for it already).
        if !prepared {
            crate::syscalls::publish_limits();
        }
        if t.inherit.foster {
            crate::reaper::foster_started(&t.line.0);
        }
        if let Some(cg) = &t.cgroup {
            // Where it starts, in case it looks before the parent writes it.
            let _ = crate::procreg::set_cgroup(crate::host::pid(), cg);
        }
        // Its root, working directory and umask: its parent's still, or
        // its own.
        crate::fsshare::forked_child(t.fs);
        if t.clear_sighand {
            self.clear_handlers();
        }
        crate::cgroupfs::forked();
        if t.frozen {
            // As a task forked into a frozen cgroup, it runs only once
            // the cgroup thaws ([`crate::signal::continue_process`]).
            crate::signal::stop_sent_now();
            crate::host::stop_with(libc::SIGSTOP);
        }
        FILES_SHARED.store(t.files, std::sync::atomic::Ordering::SeqCst);
        CLEAR_SIGHAND.store(false, std::sync::atomic::Ordering::SeqCst);
        crate::fsshare::fork_shares(false);
        crate::reaper::forked_child();
        crate::fs::forked_child_fifos();
        // A reaper: a pid namespace's init, or one its record makes one (the
        // record prepared for it never does).
        if !prepared || t.nums.first() == Some(&1) {
            crate::reaper::start_if_reaper();
        }
        t.nums.first().copied().unwrap_or_else(|| crate::host::pid().get())
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
