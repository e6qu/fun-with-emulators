//! The arguments of a `clone`, from the `clone` system call's registers or
//! from `clone3`'s `struct clone_args`, in one form the backends act on.

use fwe_abi::clone::*;
use fwe_abi::errno;

/// What a `clone` asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloneArgs {
    /// `CLONE_*` flags, with the exit signal in the `CSIGNAL` bits.
    pub flags: u64,
    /// The child's initial stack pointer, or 0 to keep the parent's.
    pub stack: u64,
    pub parent_tid: u64,
    pub tls: u64,
    pub child_tid: u64,
    /// `CLONE_INTO_CGROUP`'s descriptor of the cgroup the child starts in.
    pub cgroup: Option<i32>,
    /// Where `CLONE_PIDFD` puts the child's process descriptor (`clone`'s
    /// `parent_tid`, `clone3`'s `pidfd`).
    pub pidfd: u64,
    /// `clone3`'s chosen pids, the child's in its own pid namespace first,
    /// then in each above it (the first `set_tid_size`).
    pub set_tid: [i32; MAX_PID_NS_LEVEL],
    pub set_tid_size: usize,
}

/// The flags a thread (`CLONE_THREAD`) may be made with in fwe: the set
/// the C libraries' thread creation uses.
pub const THREAD_FLAGS: u64 = CLONE_VM
    | CLONE_FS
    | CLONE_FILES
    | CLONE_SIGHAND
    | CLONE_THREAD
    | CLONE_SYSVSEM
    | CLONE_SETTLS
    | CLONE_PARENT_SETTID
    | CLONE_CHILD_CLEARTID
    | CLONE_CHILD_SETTID
    | CLONE_DETACHED;

/// The most pid namespaces nested, and so the most pids `set_tid` names.
pub const MAX_PID_NS_LEVEL: usize = 32;

impl CloneArgs {
    /// `clone(flags, stack, parent_tid, tls, child_tid)`, the arm64 order.
    pub fn from_clone(x: &[u64]) -> CloneArgs {
        CloneArgs {
            flags: x[0],
            stack: x[1],
            parent_tid: x[2],
            tls: x[3],
            child_tid: x[4],
            cgroup: None,
            pidfd: if x[0] & CLONE_PIDFD != 0 { x[2] } else { 0 },
            set_tid: [0; MAX_PID_NS_LEVEL],
            set_tid_size: 0,
        }
    }

    /// The combinations of flags Linux refuses (`EINVAL`) whichever call
    /// asked for them.
    pub fn check(&self) -> Result<(), i32> {
        let f = self.flags;
        let both = |a: u64, b: u64| f & (a | b) == a | b;
        if both(CLONE_NEWNS, CLONE_FS)
            || both(CLONE_NEWUSER, CLONE_FS)
            // A thread shares the handlers, which share the memory.
            || (f & CLONE_THREAD != 0 && f & CLONE_SIGHAND == 0)
            || (f & CLONE_SIGHAND != 0 && f & CLONE_VM == 0)
            || (f & CLONE_THREAD != 0 && f & (CLONE_NEWUSER | CLONE_NEWPID) != 0)
            || both(CLONE_SIGHAND, CLONE_CLEAR_SIGHAND)
            // A process descriptor is of a process, and `clone`'s goes where
            // the parent's copy of the tid would.
            || (f & CLONE_PIDFD != 0 && f & (CLONE_THREAD | CLONE_DETACHED) != 0)
            || (f & CLONE_PIDFD != 0 && self.pidfd == self.parent_tid && both(CLONE_PIDFD, CLONE_PARENT_SETTID))
            // A thread's number is not chosen: fwe numbers threads itself.
            || (f & CLONE_THREAD != 0 && self.set_tid_size != 0)
        {
            return Err(errno::EINVAL);
        }
        Ok(())
    }

    /// What a new thread needs beyond [`check`](Self::check), in either
    /// backend: no flag outside [`THREAD_FLAGS`] (`ENOSYS`: fwe does not
    /// make such a thread) and a stack of its own (`EINVAL`).
    pub fn thread_flags_check(&self) -> Result<(), i32> {
        if self.flags & !THREAD_FLAGS & !CSIGNAL != 0 {
            return Err(errno::ENOSYS);
        }
        if self.stack == 0 {
            return Err(errno::EINVAL);
        }
        Ok(())
    }

    /// [`thread_flags_check`](Self::thread_flags_check), then room for
    /// one more task within `RLIMIT_NPROC` and the cgroups' `pids.max`.
    pub fn thread_check(&self) -> Result<(), i32> {
        self.thread_flags_check()?;
        crate::cgroupfs::task_allowed()
    }

    /// `clone3(args, size)`: read the guest's `struct clone_args`, and the
    /// pids `set_tid` chooses.
    pub fn from_clone3(args: u64, size: u64) -> Result<CloneArgs, i32> {
        if size < CLONE_ARGS_SIZE_VER0 {
            return Err(errno::EINVAL);
        }
        if size > 4096 {
            return Err(errno::E2BIG);
        }
        let mut raw = [0u64; (CLONE_ARGS_SIZE_VER2 / 8) as usize];
        let known = size.min(CLONE_ARGS_SIZE_VER2) as usize;
        let mut bytes = vec![0u8; size as usize];
        crate::uaccess::read_into(args, &mut bytes).map_err(|_| errno::EFAULT)?;
        // A newer structure is fine as long as what fwe does not know is 0.
        if bytes[known..].iter().any(|&b| b != 0) {
            return Err(errno::E2BIG);
        }
        for (i, w) in raw.iter_mut().enumerate().take(known / 8) {
            *w = u64::from_ne_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap());
        }
        let [
            flags,
            pidfd,
            child_tid,
            parent_tid,
            exit_signal,
            stack,
            stack_size,
            tls,
            set_tid_at,
            set_tid_size,
            cgroup,
        ] = raw;
        let legacy = (1u64 << 32) - 1;
        if flags & !(legacy | CLONE_CLEAR_SIGHAND | CLONE_INTO_CGROUP) != 0
            || flags & (CLONE_DETACHED | CSIGNAL) != 0
            || exit_signal > fwe_abi::signal::NSIG
            // A thread, or a sibling, is no child of the caller's to
            // signal its end.
            || (flags & (CLONE_THREAD | CLONE_PARENT) != 0 && exit_signal != 0)
            || cgroup > i32::MAX as u64
        {
            return Err(errno::EINVAL);
        }
        if (stack == 0) != (stack_size == 0) {
            return Err(errno::EINVAL);
        }
        if set_tid_size > MAX_PID_NS_LEVEL as u64 || (set_tid_at == 0) != (set_tid_size == 0) {
            return Err(errno::EINVAL);
        }
        let mut set_tid = [0i32; MAX_PID_NS_LEVEL];
        if set_tid_size != 0 {
            let mut b = vec![0u8; set_tid_size as usize * 4];
            crate::uaccess::read_into(set_tid_at, &mut b).map_err(|_| errno::EFAULT)?;
            for (t, w) in set_tid.iter_mut().zip(b.as_chunks::<4>().0) {
                *t = i32::from_ne_bytes(*w);
            }
        }
        Ok(CloneArgs {
            flags: flags | exit_signal,
            // The structure gives the lowest address; the stack grows down.
            stack: if stack == 0 { 0 } else { stack + stack_size },
            parent_tid,
            tls,
            child_tid,
            cgroup: (flags & CLONE_INTO_CGROUP != 0).then_some(cgroup as i32),
            pidfd: if flags & CLONE_PIDFD != 0 { pidfd } else { 0 },
            set_tid,
            set_tid_size: set_tid_size as usize,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(words: &[u64]) -> Vec<u64> {
        let mut v = vec![0u64; 11];
        v[..words.len()].copy_from_slice(words);
        v
    }

    /// A thread is made with the flags the C libraries use and a stack of
    /// its own, in either backend; another flag is `ENOSYS`, no stack
    /// `EINVAL`.
    #[test]
    fn threads_take_the_known_flags_and_a_stack() {
        let pthread = CLONE_VM
            | CLONE_FS
            | CLONE_FILES
            | CLONE_SIGHAND
            | CLONE_THREAD
            | CLONE_SYSVSEM
            | CLONE_SETTLS
            | CLONE_PARENT_SETTID
            | CLONE_CHILD_CLEARTID;
        let t = |flags, stack| CloneArgs { flags, stack, ..CloneArgs::from_clone(&[0; 6]) };
        assert_eq!(t(pthread, 0x1000).thread_flags_check(), Ok(()));
        assert_eq!(t(pthread | 17, 0x1000).thread_flags_check(), Ok(()));
        assert_eq!(t(pthread, 0).thread_flags_check(), Err(errno::EINVAL));
        for other in [CLONE_PARENT, CLONE_IO, CLONE_NEWNS, CLONE_VFORK, CLONE_INTO_CGROUP] {
            assert_eq!(t(pthread | other, 0x1000).thread_flags_check(), Err(errno::ENOSYS));
        }
    }

    #[test]
    fn clone3_becomes_clone() {
        // flags, pidfd, child_tid, parent_tid, exit_signal, stack, stack_size, tls
        let a = args(&[CLONE_VM | CLONE_THREAD, 0, 0x30, 0x40, 0, 0x1000, 0x2000, 0x50]);
        let got = CloneArgs::from_clone3(a.as_ptr() as u64, 88).unwrap();
        assert_eq!(
            got,
            CloneArgs {
                flags: CLONE_VM | CLONE_THREAD,
                stack: 0x3000,
                parent_tid: 0x40,
                tls: 0x50,
                child_tid: 0x30,
                cgroup: None,
                pidfd: 0,
                set_tid: [0; MAX_PID_NS_LEVEL],
                set_tid_size: 0,
            }
        );
        // A fork: no flags, SIGCHLD as the exit signal, the parent's stack.
        let a = args(&[0, 0, 0, 0, 17]);
        let got = CloneArgs::from_clone3(a.as_ptr() as u64, 64).unwrap();
        assert_eq!((got.flags, got.stack), (17, 0));
    }

    /// `CLONE_PIDFD`'s descriptor goes to `clone`'s parent-tid word, which
    /// `CLONE_PARENT_SETTID` cannot then have, or to `clone3`'s own field;
    /// a thread has none.
    #[test]
    fn clone_pidfd_goes_where_asked() {
        let a = CloneArgs::from_clone(&[CLONE_PIDFD | 17, 0, 0x40, 0, 0, 0]);
        assert_eq!((a.pidfd, a.check()), (0x40, Ok(())));
        let a = CloneArgs::from_clone(&[CLONE_PIDFD | CLONE_PARENT_SETTID | 17, 0, 0x40, 0, 0, 0]);
        assert_eq!(a.check(), Err(errno::EINVAL));
        let thread = CLONE_PIDFD | CLONE_THREAD | CLONE_SIGHAND | CLONE_VM;
        assert_eq!(
            CloneArgs::from_clone(&[thread, 0x1000, 0x40, 0, 0, 0]).check(),
            Err(errno::EINVAL)
        );
        let raw = args(&[CLONE_PIDFD | CLONE_PARENT_SETTID, 0x50, 0, 0x40, 17]);
        let a = CloneArgs::from_clone3(raw.as_ptr() as u64, 88).unwrap();
        assert_eq!((a.pidfd, a.parent_tid, a.check()), (0x50, 0x40, Ok(())));
    }

    #[test]
    fn clone3_refuses_what_it_cannot_do() {
        let p = |a: &Vec<u64>, size| CloneArgs::from_clone3(a.as_ptr() as u64, size);
        assert_eq!(p(&args(&[]), 56), Err(errno::EINVAL));
        assert_eq!(p(&args(&[17]), 64), Err(errno::EINVAL), "exit signal in flags");
        assert_eq!(p(&args(&[0, 0, 0, 0, 0, 0x1000]), 64), Err(errno::EINVAL), "stack, no size");
        // A size without pids, too many pids, and the pids read.
        assert_eq!(p(&args(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 1]), 88), Err(errno::EINVAL));
        let pids = [7i32, 1];
        let at = pids.as_ptr() as u64;
        assert_eq!(p(&args(&[0, 0, 0, 0, 0, 0, 0, 0, at, 33]), 88), Err(errno::EINVAL));
        let got = p(&args(&[0, 0, 0, 0, 17, 0, 0, 0, at, 2]), 88).unwrap();
        assert_eq!((got.set_tid_size, &got.set_tid[..2]), (2, &pids[..]));
        // Unknown trailing fields must be zero.
        let mut big = args(&[]);
        big.extend([0, 7]);
        assert_eq!(p(&big, 104), Err(errno::E2BIG));
        big[12] = 0;
        assert!(p(&big, 104).is_ok());
    }

    /// The combinations Linux refuses, whichever call asks for them, and
    /// clone3's own rules.
    #[test]
    fn refused_combinations() {
        let with = |flags| CloneArgs::from_clone(&[flags, 0, 0, 0, 0]).check();
        assert_eq!(with(CLONE_SIGHAND), Err(errno::EINVAL));
        assert_eq!(with(CLONE_THREAD | CLONE_VM), Err(errno::EINVAL));
        assert_eq!(with(CLONE_FS | CLONE_NEWNS), Err(errno::EINVAL));
        assert_eq!(with(CLONE_FS | CLONE_NEWUSER), Err(errno::EINVAL));
        assert_eq!(
            with(CLONE_THREAD | CLONE_SIGHAND | CLONE_VM | CLONE_NEWPID),
            Err(errno::EINVAL)
        );
        assert_eq!(with(CLONE_THREAD | CLONE_SIGHAND | CLONE_VM), Ok(()));
        assert_eq!(with(CLONE_VM | 17), Ok(()));
        let p = |w: &[u64]| {
            let a = args(w);
            CloneArgs::from_clone3(a.as_ptr() as u64, 88)
        };
        // A thread with an exit signal; CLONE_DETACHED; both handler flags.
        assert_eq!(p(&[CLONE_VM | CLONE_SIGHAND | CLONE_THREAD, 0, 0, 0, 17]), Err(errno::EINVAL));
        assert_eq!(p(&[CLONE_DETACHED, 0, 0, 0, 17]), Err(errno::EINVAL));
        let got = p(&[CLONE_SIGHAND | CLONE_CLEAR_SIGHAND | CLONE_VM, 0, 0, 0, 17]).unwrap();
        assert_eq!(got.check(), Err(errno::EINVAL));
        // A cgroup, by descriptor.
        let a = args(&[CLONE_INTO_CGROUP, 0, 0, 0, 17, 0, 0, 0, 0, 0, 5]);
        assert_eq!(CloneArgs::from_clone3(a.as_ptr() as u64, 88).unwrap().cgroup, Some(5));
    }
}
