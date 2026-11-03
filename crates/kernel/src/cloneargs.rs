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
}

impl CloneArgs {
    /// `clone(flags, stack, parent_tid, tls, child_tid)`, the arm64 order.
    pub fn from_clone(x: &[u64]) -> CloneArgs {
        CloneArgs { flags: x[0], stack: x[1], parent_tid: x[2], tls: x[3], child_tid: x[4] }
    }

    /// `clone3(args, size)`: read the guest's `struct clone_args`. Features
    /// fwe does not have (a pidfd, chosen tids, a cgroup, clearing the
    /// handlers) fail with `ENOSYS`, so a C library falls back to `clone`.
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
            _pidfd,
            child_tid,
            parent_tid,
            exit_signal,
            stack,
            stack_size,
            tls,
            _set_tid,
            set_tid_size,
            _cgroup,
        ] = raw;
        if flags & CSIGNAL != 0 || exit_signal > fwe_abi::signal::NSIG {
            return Err(errno::EINVAL);
        }
        if (stack == 0) != (stack_size == 0) {
            return Err(errno::EINVAL);
        }
        if flags & (CLONE_PIDFD | CLONE_INTO_CGROUP | CLONE_CLEAR_SIGHAND) != 0 || set_tid_size != 0
        {
            return Err(errno::ENOSYS);
        }
        Ok(CloneArgs {
            flags: flags | exit_signal,
            // The structure gives the lowest address; the stack grows down.
            stack: if stack == 0 { 0 } else { stack + stack_size },
            parent_tid,
            tls,
            child_tid,
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
                child_tid: 0x30
            }
        );
        // A fork: no flags, SIGCHLD as the exit signal, the parent's stack.
        let a = args(&[0, 0, 0, 0, 17]);
        let got = CloneArgs::from_clone3(a.as_ptr() as u64, 64).unwrap();
        assert_eq!((got.flags, got.stack), (17, 0));
    }

    #[test]
    fn clone3_refuses_what_it_cannot_do() {
        let p = |a: &Vec<u64>, size| CloneArgs::from_clone3(a.as_ptr() as u64, size);
        assert_eq!(p(&args(&[]), 56), Err(errno::EINVAL));
        assert_eq!(p(&args(&[17]), 64), Err(errno::EINVAL), "exit signal in flags");
        assert_eq!(p(&args(&[0, 0, 0, 0, 0, 0x1000]), 64), Err(errno::EINVAL), "stack, no size");
        assert_eq!(p(&args(&[CLONE_PIDFD]), 64), Err(errno::ENOSYS));
        assert_eq!(p(&args(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 1]), 88), Err(errno::ENOSYS));
        // Unknown trailing fields must be zero.
        let mut big = args(&[]);
        big.extend([0, 7]);
        assert_eq!(p(&big, 104), Err(errno::E2BIG));
        big[12] = 0;
        assert!(p(&big, 104).is_ok());
    }
}
