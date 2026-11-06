//! Linux arm64 userspace ABI definitions.
//!
//! Numbers and layouts here describe what Linux binaries expect. They are
//! independent of the host: translation to macOS happens in the kernel crate.
//!
//! [`nr`], [`errno`], [`syscall_name`] and [`errno_name`] are generated from
//! the Linux UAPI headers by `tools/gen-abi.py`; everything else is
//! hand-written from the same headers.

#![no_std]

mod generated;

pub use generated::{SYSCALL_COUNT, errno, errno_name, nr, syscall_name};

/// Page size reported to guests through `AT_PAGESZ`.
///
/// The arm64 Linux ABI permits 4K, 16K and 64K pages; Apple Silicon uses 16K.
pub const PAGE_SIZE: u64 = 16384;

/// Auxiliary vector entry types (`linux/auxvec.h`, `asm/auxvec.h`).
pub mod auxv {
    pub const AT_NULL: u64 = 0;
    pub const AT_IGNORE: u64 = 1;
    pub const AT_EXECFD: u64 = 2;
    pub const AT_PHDR: u64 = 3;
    pub const AT_PHENT: u64 = 4;
    pub const AT_PHNUM: u64 = 5;
    pub const AT_PAGESZ: u64 = 6;
    pub const AT_BASE: u64 = 7;
    pub const AT_FLAGS: u64 = 8;
    pub const AT_ENTRY: u64 = 9;
    pub const AT_NOTELF: u64 = 10;
    pub const AT_UID: u64 = 11;
    pub const AT_EUID: u64 = 12;
    pub const AT_GID: u64 = 13;
    pub const AT_EGID: u64 = 14;
    pub const AT_PLATFORM: u64 = 15;
    pub const AT_HWCAP: u64 = 16;
    pub const AT_CLKTCK: u64 = 17;
    pub const AT_SECURE: u64 = 23;
    pub const AT_BASE_PLATFORM: u64 = 24;
    pub const AT_RANDOM: u64 = 25;
    pub const AT_HWCAP2: u64 = 26;
    pub const AT_RSEQ_FEATURE_SIZE: u64 = 27;
    pub const AT_RSEQ_ALIGN: u64 = 28;
    pub const AT_HWCAP3: u64 = 29;
    pub const AT_HWCAP4: u64 = 30;
    pub const AT_EXECFN: u64 = 31;
    pub const AT_SYSINFO_EHDR: u64 = 33;
    pub const AT_MINSIGSTKSZ: u64 = 51;
}

/// `AT_HWCAP` bits (`arch/arm64/include/uapi/asm/hwcap.h`).
pub mod hwcap {
    pub const FP: u64 = 1 << 0;
    pub const ASIMD: u64 = 1 << 1;
    pub const EVTSTRM: u64 = 1 << 2;
    pub const AES: u64 = 1 << 3;
    pub const PMULL: u64 = 1 << 4;
    pub const SHA1: u64 = 1 << 5;
    pub const SHA2: u64 = 1 << 6;
    pub const CRC32: u64 = 1 << 7;
    pub const ATOMICS: u64 = 1 << 8;
    pub const FPHP: u64 = 1 << 9;
    pub const ASIMDHP: u64 = 1 << 10;
    pub const CPUID: u64 = 1 << 11;
    pub const ASIMDRDM: u64 = 1 << 12;
    pub const JSCVT: u64 = 1 << 13;
    pub const FCMA: u64 = 1 << 14;
    pub const LRCPC: u64 = 1 << 15;
    pub const DCPOP: u64 = 1 << 16;
    pub const SHA3: u64 = 1 << 17;
    pub const SM3: u64 = 1 << 18;
    pub const SM4: u64 = 1 << 19;
    pub const ASIMDDP: u64 = 1 << 20;
    pub const SHA512: u64 = 1 << 21;
    pub const SVE: u64 = 1 << 22;
    pub const ASIMDFHM: u64 = 1 << 23;
    pub const DIT: u64 = 1 << 24;
    pub const USCAT: u64 = 1 << 25;
    pub const ILRCPC: u64 = 1 << 26;
    pub const FLAGM: u64 = 1 << 27;
    pub const SSBS: u64 = 1 << 28;
    pub const SB: u64 = 1 << 29;
    pub const PACA: u64 = 1 << 30;
    pub const PACG: u64 = 1 << 31;
}

/// `AT_HWCAP2` bits (`arch/arm64/include/uapi/asm/hwcap.h`).
pub mod hwcap2 {
    pub const DCPODP: u64 = 1 << 0;
    pub const SVE2: u64 = 1 << 1;
    pub const SVEAES: u64 = 1 << 2;
    pub const SVEPMULL: u64 = 1 << 3;
    pub const SVEBITPERM: u64 = 1 << 4;
    pub const SVESHA3: u64 = 1 << 5;
    pub const SVESM4: u64 = 1 << 6;
    pub const FLAGM2: u64 = 1 << 7;
    pub const FRINT: u64 = 1 << 8;
    pub const SVEI8MM: u64 = 1 << 9;
    pub const SVEF32MM: u64 = 1 << 10;
    pub const SVEF64MM: u64 = 1 << 11;
    pub const SVEBF16: u64 = 1 << 12;
    pub const I8MM: u64 = 1 << 13;
    pub const BF16: u64 = 1 << 14;
    pub const DGH: u64 = 1 << 15;
    pub const RNG: u64 = 1 << 16;
    pub const BTI: u64 = 1 << 17;
    pub const MTE: u64 = 1 << 18;
    pub const ECV: u64 = 1 << 19;
    pub const AFP: u64 = 1 << 20;
    pub const RPRES: u64 = 1 << 21;
    pub const MTE3: u64 = 1 << 22;
    pub const SME: u64 = 1 << 23;
    pub const SME_I16I64: u64 = 1 << 24;
    pub const SME_F64F64: u64 = 1 << 25;
    pub const SME_I8I32: u64 = 1 << 26;
    pub const SME_F16F32: u64 = 1 << 27;
    pub const SME_B16F32: u64 = 1 << 28;
    pub const SME_F32F32: u64 = 1 << 29;
    pub const SME_FA64: u64 = 1 << 30;
    pub const WFXT: u64 = 1 << 31;
    pub const EBF16: u64 = 1 << 32;
    pub const SVE_EBF16: u64 = 1 << 33;
    pub const CSSC: u64 = 1 << 34;
    pub const RPRFM: u64 = 1 << 35;
    pub const SVE2P1: u64 = 1 << 36;
    pub const SME2: u64 = 1 << 37;
    pub const SME2P1: u64 = 1 << 38;
    pub const SME_I16I32: u64 = 1 << 39;
    pub const SME_BI32I32: u64 = 1 << 40;
    pub const SME_B16B16: u64 = 1 << 41;
    pub const SME_F16F16: u64 = 1 << 42;
    pub const MOPS: u64 = 1 << 43;
    pub const HBC: u64 = 1 << 44;
}

/// Memory protection and mapping flags (`asm-generic/mman*.h`).
pub mod mman {
    pub const PROT_NONE: u64 = 0;
    pub const PROT_READ: u64 = 1;
    pub const PROT_WRITE: u64 = 2;
    pub const PROT_EXEC: u64 = 4;
    pub const PROT_BTI: u64 = 0x10;
    pub const PROT_MTE: u64 = 0x20;

    pub const MAP_SHARED: u64 = 0x01;
    pub const MAP_PRIVATE: u64 = 0x02;
    pub const MAP_SHARED_VALIDATE: u64 = 0x03;
    pub const MAP_TYPE: u64 = 0x0f;
    pub const MAP_FIXED: u64 = 0x10;
    pub const MAP_ANONYMOUS: u64 = 0x20;
    pub const MAP_GROWSDOWN: u64 = 0x0100;
    pub const MAP_DENYWRITE: u64 = 0x0800;
    pub const MAP_EXECUTABLE: u64 = 0x1000;
    pub const MAP_LOCKED: u64 = 0x2000;
    pub const MAP_NORESERVE: u64 = 0x4000;
    pub const MAP_POPULATE: u64 = 0x8000;
    pub const MAP_NONBLOCK: u64 = 0x10000;
    pub const MAP_STACK: u64 = 0x20000;
    pub const MAP_HUGETLB: u64 = 0x40000;
    pub const MAP_SYNC: u64 = 0x80000;
    pub const MAP_FIXED_NOREPLACE: u64 = 0x100000;

    pub const MREMAP_MAYMOVE: u64 = 1;
    pub const MREMAP_FIXED: u64 = 2;
    pub const MREMAP_DONTUNMAP: u64 = 4;

    pub const MADV_NORMAL: u64 = 0;
    pub const MADV_RANDOM: u64 = 1;
    pub const MADV_SEQUENTIAL: u64 = 2;
    pub const MADV_WILLNEED: u64 = 3;
    pub const MADV_DONTNEED: u64 = 4;
    pub const MADV_FREE: u64 = 8;
}

/// File status flags (`asm-generic/fcntl.h`, arm64 overrides).
/// `prctl` options.
pub mod prctl {
    pub const PR_SET_PDEATHSIG: u64 = 1;
    pub const PR_GET_PDEATHSIG: u64 = 2;
    pub const PR_GET_DUMPABLE: u64 = 3;
    pub const PR_SET_DUMPABLE: u64 = 4;
    pub const PR_SET_NAME: u64 = 15;
    pub const PR_GET_NAME: u64 = 16;
    pub const PR_GET_KEEPCAPS: u64 = 7;
    pub const PR_SET_KEEPCAPS: u64 = 8;
    pub const PR_GET_SECCOMP: u64 = 21;
    pub const PR_SET_SECCOMP: u64 = 22;
    pub const PR_CAPBSET_READ: u64 = 23;
    pub const PR_CAPBSET_DROP: u64 = 24;
    pub const PR_GET_SECUREBITS: u64 = 27;
    pub const PR_SET_SECUREBITS: u64 = 28;
    pub const PR_SET_CHILD_SUBREAPER: u64 = 36;
    pub const PR_GET_CHILD_SUBREAPER: u64 = 37;
    pub const PR_CAP_AMBIENT: u64 = 47;
    pub const PR_SET_NO_NEW_PRIVS: u64 = 38;
    pub const PR_GET_NO_NEW_PRIVS: u64 = 39;
    /// Reset pointer-authentication keys (arm64): which, a mask of
    /// `PR_PAC_AP*KEY`, or 0 for all.
    pub const PR_PAC_RESET_KEYS: u64 = 54;
    pub const PR_PAC_APIAKEY: u64 = 1 << 0;
    pub const PR_PAC_APIBKEY: u64 = 1 << 1;
    pub const PR_PAC_APDAKEY: u64 = 1 << 2;
    pub const PR_PAC_APDBKEY: u64 = 1 << 3;
    pub const PR_PAC_APGAKEY: u64 = 1 << 4;
    /// The highest capability number (`CAP_CHECKPOINT_RESTORE`).
    pub const CAP_LAST_CAP: u64 = 40;
    /// `TASK_COMM_LEN`: a thread name and its terminating NUL.
    pub const TASK_COMM_LEN: usize = 16;
}

pub mod fcntl {
    pub const O_ACCMODE: u64 = 0o3;
    pub const O_RDONLY: u64 = 0o0;
    pub const O_WRONLY: u64 = 0o1;
    pub const O_RDWR: u64 = 0o2;
    pub const O_CREAT: u64 = 0o100;
    pub const O_EXCL: u64 = 0o200;
    pub const O_NOCTTY: u64 = 0o400;
    pub const O_TRUNC: u64 = 0o1000;
    pub const O_APPEND: u64 = 0o2000;
    pub const O_NONBLOCK: u64 = 0o4000;
    pub const O_DSYNC: u64 = 0o10000;
    pub const O_ASYNC: u64 = 0o20000;
    // arm64 moves these four relative to asm-generic.
    pub const O_DIRECTORY: u64 = 0o40000;
    pub const O_NOFOLLOW: u64 = 0o100000;
    pub const O_DIRECT: u64 = 0o200000;
    pub const O_LARGEFILE: u64 = 0o400000;
    pub const O_NOATIME: u64 = 0o1000000;
    pub const O_CLOEXEC: u64 = 0o2000000;
    pub const O_SYNC: u64 = 0o4010000;
    pub const O_PATH: u64 = 0o10000000;
    pub const O_TMPFILE: u64 = 0o20040000;

    pub const F_DUPFD: u64 = 0;
    pub const F_GETFD: u64 = 1;
    pub const F_SETFD: u64 = 2;
    pub const F_GETFL: u64 = 3;
    pub const F_SETFL: u64 = 4;
    pub const F_GETLK: u64 = 5;
    pub const F_SETLK: u64 = 6;
    pub const F_SETLKW: u64 = 7;
    pub const F_OFD_GETLK: u64 = 36;
    pub const F_OFD_SETLK: u64 = 37;
    pub const F_OFD_SETLKW: u64 = 38;
    pub const F_DUPFD_CLOEXEC: u64 = 1030;
    pub const F_ADD_SEALS: u64 = 1033;
    pub const F_GET_SEALS: u64 = 1034;

    /// File seals (`F_ADD_SEALS`).
    pub const F_SEAL_SEAL: u32 = 0x1;
    pub const F_SEAL_SHRINK: u32 = 0x2;
    pub const F_SEAL_GROW: u32 = 0x4;
    pub const F_SEAL_WRITE: u32 = 0x8;
    pub const F_SEAL_FUTURE_WRITE: u32 = 0x10;
    pub const F_SEAL_EXEC: u32 = 0x20;

    /// `struct flock` lock types.
    pub const F_RDLCK: i16 = 0;
    pub const F_WRLCK: i16 = 1;
    pub const F_UNLCK: i16 = 2;

    /// `flock` operations.
    pub const LOCK_SH: u64 = 1;
    pub const LOCK_EX: u64 = 2;
    pub const LOCK_NB: u64 = 4;
    pub const LOCK_UN: u64 = 8;

    pub const FD_CLOEXEC: u64 = 1;

    pub const AT_FDCWD: i64 = -100;
    pub const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
    pub const AT_REMOVEDIR: u64 = 0x200;
    pub const AT_SYMLINK_FOLLOW: u64 = 0x400;
    pub const AT_NO_AUTOMOUNT: u64 = 0x800;
    pub const AT_EMPTY_PATH: u64 = 0x1000;

    /// `faccessat` mode bits.
    pub const F_OK: u64 = 0;
    pub const X_OK: u64 = 1;
    pub const W_OK: u64 = 2;
    pub const R_OK: u64 = 4;

    /// `lseek` whence values.
    pub const SEEK_SET: u64 = 0;
    pub const SEEK_CUR: u64 = 1;
    pub const SEEK_END: u64 = 2;
}

/// File type and mode bits (`st_mode`, `S_IF*`).
pub mod stat {
    pub const S_IFMT: u32 = 0o170000;
    pub const S_IFSOCK: u32 = 0o140000;
    pub const S_IFLNK: u32 = 0o120000;
    pub const S_IFREG: u32 = 0o100000;
    pub const S_IFBLK: u32 = 0o060000;
    pub const S_IFDIR: u32 = 0o040000;
    pub const S_IFCHR: u32 = 0o020000;
    pub const S_IFIFO: u32 = 0o010000;

    /// `d_type` values for `getdents64` and the high nibble of `st_mode`.
    pub const DT_UNKNOWN: u8 = 0;
    pub const DT_FIFO: u8 = 1;
    pub const DT_CHR: u8 = 2;
    pub const DT_DIR: u8 = 4;
    pub const DT_BLK: u8 = 6;
    pub const DT_REG: u8 = 8;
    pub const DT_LNK: u8 = 10;
    pub const DT_SOCK: u8 = 12;
}

/// `statx` field-mask bits (`linux/stat.h`).
pub mod statx_mask {
    pub const STATX_TYPE: u32 = 0x0001;
    pub const STATX_MODE: u32 = 0x0002;
    pub const STATX_NLINK: u32 = 0x0004;
    pub const STATX_UID: u32 = 0x0008;
    pub const STATX_GID: u32 = 0x0010;
    pub const STATX_ATIME: u32 = 0x0020;
    pub const STATX_MTIME: u32 = 0x0040;
    pub const STATX_CTIME: u32 = 0x0080;
    pub const STATX_INO: u32 = 0x0100;
    pub const STATX_SIZE: u32 = 0x0200;
    pub const STATX_BLOCKS: u32 = 0x0400;
    pub const STATX_BASIC_STATS: u32 = 0x07ff;
}

/// Clock identifiers (`linux/time.h`).
pub mod clock {
    pub const CLOCK_REALTIME: u64 = 0;
    pub const CLOCK_MONOTONIC: u64 = 1;
    pub const CLOCK_PROCESS_CPUTIME_ID: u64 = 2;
    pub const CLOCK_THREAD_CPUTIME_ID: u64 = 3;
    pub const CLOCK_MONOTONIC_RAW: u64 = 4;
    pub const CLOCK_REALTIME_COARSE: u64 = 5;
    pub const CLOCK_MONOTONIC_COARSE: u64 = 6;
    pub const CLOCK_BOOTTIME: u64 = 7;
    pub const CLOCK_REALTIME_ALARM: u64 = 8;
    pub const CLOCK_BOOTTIME_ALARM: u64 = 9;
    pub const CLOCK_TAI: u64 = 11;
}

/// Signal numbers (`asm-generic/signal.h`).
pub mod signal {
    pub const SIGHUP: u64 = 1;
    pub const SIGINT: u64 = 2;
    pub const SIGQUIT: u64 = 3;
    pub const SIGILL: u64 = 4;
    pub const SIGTRAP: u64 = 5;
    pub const SIGABRT: u64 = 6;
    pub const SIGBUS: u64 = 7;
    pub const SIGFPE: u64 = 8;
    pub const SIGKILL: u64 = 9;
    pub const SIGUSR1: u64 = 10;
    pub const SIGSEGV: u64 = 11;
    pub const SIGUSR2: u64 = 12;
    pub const SIGPIPE: u64 = 13;
    pub const SIGALRM: u64 = 14;
    pub const SIGTERM: u64 = 15;
    pub const SIGSTKFLT: u64 = 16;
    pub const SIGCHLD: u64 = 17;
    pub const SIGCONT: u64 = 18;
    pub const SIGSTOP: u64 = 19;
    pub const SIGTSTP: u64 = 20;
    pub const SIGTTIN: u64 = 21;
    pub const SIGTTOU: u64 = 22;
    pub const SIGURG: u64 = 23;
    pub const SIGXCPU: u64 = 24;
    pub const SIGXFSZ: u64 = 25;
    pub const SIGVTALRM: u64 = 26;
    pub const SIGPROF: u64 = 27;
    pub const SIGWINCH: u64 = 28;
    pub const SIGIO: u64 = 29;
    pub const SIGPWR: u64 = 30;
    pub const SIGSYS: u64 = 31;
    pub const SIGRTMIN: u64 = 32;
    pub const NSIG: u64 = 64;

    pub const SIG_BLOCK: u64 = 0;
    pub const SIG_UNBLOCK: u64 = 1;
    pub const SIG_SETMASK: u64 = 2;

    /// Size of the kernel `sigset_t` on arm64.
    pub const SIGSET_SIZE: u64 = 8;

    /// Minimum signal stack size reported via `AT_MINSIGSTKSZ` (no SVE/SME).
    pub const MINSIGSTKSZ: u64 = 5120;

    /// Handler sentinels.
    pub const SIG_DFL: u64 = 0;
    pub const SIG_IGN: u64 = 1;

    /// `sa_flags` bits (`asm-generic/signal.h`).
    pub const SA_NOCLDSTOP: u64 = 1;
    pub const SA_NOCLDWAIT: u64 = 2;
    pub const SA_SIGINFO: u64 = 4;
    pub const SA_RESTORER: u64 = 0x0400_0000;
    pub const SA_ONSTACK: u64 = 0x0800_0000;
    pub const SA_RESTART: u64 = 0x1000_0000;
    pub const SA_NODEFER: u64 = 0x4000_0000;
    pub const SA_RESETHAND: u64 = 0x8000_0000;

    /// `ss_flags` bits.
    pub const SS_ONSTACK: i32 = 1;
    pub const SS_DISABLE: i32 = 2;

    /// `si_code` values shared across signals.
    pub const SI_USER: i32 = 0;
    pub const SI_KERNEL: i32 = 0x80;
    pub const SI_QUEUE: i32 = -1;
    pub const SI_TIMER: i32 = -2;
    pub const SI_MESGQ: i32 = -3;
    pub const SI_ASYNCIO: i32 = -4;
    pub const SI_TKILL: i32 = -6;

    /// Magic and size of the `fpsimd_context` record in a signal frame's
    /// `__reserved` area.
    pub const FPSIMD_MAGIC: u32 = 0x4650_8001;
    pub const FPSIMD_CONTEXT_SIZE: u32 = 528;

    /// What a signal does when its handler is `SIG_DFL`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Default {
        Terminate,
        Ignore,
        Stop,
        Continue,
    }

    pub fn default_action(sig: u64) -> Default {
        match sig {
            SIGCHLD | SIGURG | SIGWINCH => Default::Ignore,
            SIGCONT => Default::Continue,
            SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU => Default::Stop,
            _ => Default::Terminate,
        }
    }
}

/// Terminal ioctls (`asm-generic/ioctls.h`).
pub mod ioctl {
    pub const TCGETS: u64 = 0x5401;
    pub const TCSETS: u64 = 0x5402;
    pub const TCSETSW: u64 = 0x5403;
    pub const TCSETSF: u64 = 0x5404;
    pub const TIOCGPGRP: u64 = 0x540f;
    pub const TIOCSPGRP: u64 = 0x5410;
    pub const TIOCGWINSZ: u64 = 0x5413;
    pub const TIOCSWINSZ: u64 = 0x5414;
    pub const TIOCSCTTY: u64 = 0x540e;
    pub const TIOCNOTTY: u64 = 0x5422;
    pub const TIOCGPTN: u64 = 0x8004_5430;
    pub const TIOCSPTLCK: u64 = 0x4004_5431;
    pub const FIONREAD: u64 = 0x541b;
    pub const FIONBIO: u64 = 0x5421;
    pub const FIOCLEX: u64 = 0x5451;
    pub const FIONCLEX: u64 = 0x5450;
    /// Network interface requests on a socket (`struct ifreq`).
    pub const SIOCGIFNAME: u64 = 0x8910;
    pub const SIOCGIFFLAGS: u64 = 0x8913;
    pub const SIOCSIFFLAGS: u64 = 0x8914;
    pub const SIOCGIFMTU: u64 = 0x8921;
    pub const SIOCGIFINDEX: u64 = 0x8933;
    /// `IFF_*` interface flags.
    pub const IFF_UP: u16 = 0x1;
    pub const IFF_LOOPBACK: u16 = 0x8;
    pub const IFF_RUNNING: u16 = 0x40;
}

/// `struct termios` fields (Linux asm-generic, arm64). The guest layout is
/// `c_iflag, c_oflag, c_cflag, c_lflag` (4 × u32), `c_line` (u8), then
/// `c_cc[NCCS]`; baud is encoded in `c_cflag`. `crates/kernel/src/term.rs`
/// translates to the host `termios` on macOS and passes through on Linux.
pub mod term {
    /// Byte size of the Linux `struct termios` (16 + 1 + 19).
    pub const TERMIOS_SIZE: usize = 36;
    /// Number of control characters.
    pub const NCCS: usize = 19;

    // c_iflag
    pub const IGNBRK: u32 = 0x0001;
    pub const BRKINT: u32 = 0x0002;
    pub const IGNPAR: u32 = 0x0004;
    pub const PARMRK: u32 = 0x0008;
    pub const INPCK: u32 = 0x0010;
    pub const ISTRIP: u32 = 0x0020;
    pub const INLCR: u32 = 0x0040;
    pub const IGNCR: u32 = 0x0080;
    pub const ICRNL: u32 = 0x0100;
    pub const IXON: u32 = 0x0400;
    pub const IXANY: u32 = 0x0800;
    pub const IXOFF: u32 = 0x1000;
    pub const IMAXBEL: u32 = 0x2000;
    pub const IUTF8: u32 = 0x4000;

    // c_oflag
    pub const OPOST: u32 = 0x0001;
    pub const ONLCR: u32 = 0x0004;
    pub const OCRNL: u32 = 0x0008;
    pub const ONOCR: u32 = 0x0010;
    pub const ONLRET: u32 = 0x0020;
    pub const OFILL: u32 = 0x0040;
    pub const OFDEL: u32 = 0x0080;

    // c_cflag
    pub const CSIZE: u32 = 0x0030;
    pub const CS5: u32 = 0x0000;
    pub const CS6: u32 = 0x0010;
    pub const CS7: u32 = 0x0020;
    pub const CS8: u32 = 0x0030;
    pub const CSTOPB: u32 = 0x0040;
    pub const CREAD: u32 = 0x0080;
    pub const PARENB: u32 = 0x0100;
    pub const PARODD: u32 = 0x0200;
    pub const HUPCL: u32 = 0x0400;
    pub const CLOCAL: u32 = 0x0800;
    /// `B38400`, the fixed baud reported on macOS.
    pub const B38400: u32 = 0x000f;

    // c_lflag
    pub const ISIG: u32 = 0x0001;
    pub const ICANON: u32 = 0x0002;
    pub const ECHO: u32 = 0x0008;
    pub const ECHOE: u32 = 0x0010;
    pub const ECHOK: u32 = 0x0020;
    pub const ECHONL: u32 = 0x0040;
    pub const NOFLSH: u32 = 0x0080;
    pub const TOSTOP: u32 = 0x0100;
    pub const ECHOCTL: u32 = 0x0200;
    pub const ECHOPRT: u32 = 0x0400;
    pub const ECHOKE: u32 = 0x0800;
    pub const FLUSHO: u32 = 0x1000;
    pub const PENDIN: u32 = 0x4000;
    pub const IEXTEN: u32 = 0x8000;
    pub const EXTPROC: u32 = 0x10000;

    // c_cc indices (Linux).
    pub const VINTR: usize = 0;
    pub const VQUIT: usize = 1;
    pub const VERASE: usize = 2;
    pub const VKILL: usize = 3;
    pub const VEOF: usize = 4;
    pub const VTIME: usize = 5;
    pub const VMIN: usize = 6;
    pub const VSTART: usize = 8;
    pub const VSTOP: usize = 9;
    pub const VSUSP: usize = 10;
    pub const VEOL: usize = 11;
    pub const VREPRINT: usize = 12;
    pub const VDISCARD: usize = 13;
    pub const VWERASE: usize = 14;
    pub const VLNEXT: usize = 15;
    pub const VEOL2: usize = 16;
}

/// Resource limits (`asm-generic/resource.h`).
pub mod resource {
    pub const RLIMIT_CPU: u64 = 0;
    pub const RLIMIT_FSIZE: u64 = 1;
    pub const RLIMIT_DATA: u64 = 2;
    pub const RLIMIT_STACK: u64 = 3;
    pub const RLIMIT_CORE: u64 = 4;
    pub const RLIMIT_RSS: u64 = 5;
    pub const RLIMIT_NPROC: u64 = 6;
    pub const RLIMIT_NOFILE: u64 = 7;
    pub const RLIMIT_MEMLOCK: u64 = 8;
    pub const RLIMIT_AS: u64 = 9;
    pub const RLIMIT_LOCKS: u64 = 10;
    pub const RLIMIT_SIGPENDING: u64 = 11;
    pub const RLIMIT_MSGQUEUE: u64 = 12;
    pub const RLIMIT_NICE: u64 = 13;
    pub const RLIMIT_RTPRIO: u64 = 14;
    pub const RLIMIT_RTTIME: u64 = 15;
    pub const RLIM_NLIMITS: u64 = 16;
    pub const RLIM_INFINITY: u64 = u64::MAX;
}

/// Futex operations (`linux/futex.h`).
pub mod futex {
    pub const FUTEX_WAIT: u64 = 0;
    pub const FUTEX_WAKE: u64 = 1;
    pub const FUTEX_REQUEUE: u64 = 3;
    pub const FUTEX_WAIT_BITSET: u64 = 9;
    pub const FUTEX_WAKE_BITSET: u64 = 10;
    pub const FUTEX_PRIVATE_FLAG: u64 = 128;
    pub const FUTEX_CLOCK_REALTIME: u64 = 256;
    pub const FUTEX_CMD_MASK: u64 = !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
}

/// `wait4`/`waitid` options (`linux/wait.h`).
pub mod wait {
    pub const WNOHANG: u64 = 1;
    pub const WUNTRACED: u64 = 2;
    pub const WCONTINUED: u64 = 8;
    /// `waitid` options.
    pub const WSTOPPED: u64 = 2;
    pub const WEXITED: u64 = 4;
    pub const WNOWAIT: u64 = 0x0100_0000;
    /// `waitid` id types.
    pub const P_ALL: u64 = 0;
    pub const P_PID: u64 = 1;
    pub const P_PGID: u64 = 2;
    /// `si_code` values for `SIGCHLD`.
    pub const CLD_EXITED: i32 = 1;
    pub const CLD_KILLED: i32 = 2;
    pub const CLD_DUMPED: i32 = 3;
    pub const CLD_STOPPED: i32 = 5;
    pub const CLD_CONTINUED: i32 = 6;
}

/// `getrusage` targets and `setitimer` timers.
pub mod resource_usage {
    pub const RUSAGE_SELF: i64 = 0;
    pub const RUSAGE_CHILDREN: i64 = -1;
    pub const RUSAGE_THREAD: i64 = 1;
    /// Size of `struct rusage` on 64-bit Linux.
    pub const RUSAGE_SIZE: usize = 144;
    pub const ITIMER_REAL: u64 = 0;
    pub const ITIMER_VIRTUAL: u64 = 1;
    pub const ITIMER_PROF: u64 = 2;
}

/// `clone` flags (`linux/sched.h`); the low byte is the exit signal.
pub mod clone {
    pub const CSIGNAL: u64 = 0x0000_00ff;
    pub const CLONE_VM: u64 = 0x0000_0100;
    pub const CLONE_FS: u64 = 0x0000_0200;
    pub const CLONE_FILES: u64 = 0x0000_0400;
    pub const CLONE_SIGHAND: u64 = 0x0000_0800;
    pub const CLONE_PIDFD: u64 = 0x0000_1000;
    pub const CLONE_VFORK: u64 = 0x0000_4000;
    pub const CLONE_PARENT: u64 = 0x0000_8000;
    pub const CLONE_THREAD: u64 = 0x0001_0000;
    pub const CLONE_NEWNS: u64 = 0x0002_0000;
    pub const CLONE_SYSVSEM: u64 = 0x0004_0000;
    pub const CLONE_SETTLS: u64 = 0x0008_0000;
    pub const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
    pub const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;
    pub const CLONE_DETACHED: u64 = 0x0040_0000;
    pub const CLONE_NEWCGROUP: u64 = 0x0200_0000;
    pub const CLONE_CHILD_SETTID: u64 = 0x0100_0000;
    pub const CLONE_NEWUTS: u64 = 0x0400_0000;
    pub const CLONE_NEWIPC: u64 = 0x0800_0000;
    pub const CLONE_NEWUSER: u64 = 0x1000_0000;
    pub const CLONE_NEWPID: u64 = 0x2000_0000;
    pub const CLONE_NEWNET: u64 = 0x4000_0000;
    pub const CLONE_IO: u64 = 0x8000_0000;
    /// `unshare` and `setns` only.
    pub const CLONE_NEWTIME: u64 = 0x0000_0080;
    /// Every namespace a `clone` or `unshare` can make.
    pub const CLONE_NEW_ANY: u64 = CLONE_NEWNS
        | CLONE_NEWCGROUP
        | CLONE_NEWUTS
        | CLONE_NEWIPC
        | CLONE_NEWUSER
        | CLONE_NEWPID
        | CLONE_NEWNET;
    pub const CLONE_CLEAR_SIGHAND: u64 = 0x1_0000_0000;
    pub const CLONE_INTO_CGROUP: u64 = 0x2_0000_0000;
    /// The size of the first `struct clone_args` (`CLONE_ARGS_SIZE_VER0`).
    pub const CLONE_ARGS_SIZE_VER0: u64 = 64;
    /// The size of `struct clone_args` with every field this ABI knows,
    /// through `cgroup` (`CLONE_ARGS_SIZE_VER2`).
    pub const CLONE_ARGS_SIZE_VER2: u64 = 88;
}

/// `epoll` control ops, flags and event bits (`linux/eventpoll.h`).
pub mod epoll {
    /// `epoll_create1` flag; the value of `O_CLOEXEC`.
    pub const EPOLL_CLOEXEC: u64 = 0o2000000;

    pub const EPOLL_CTL_ADD: u64 = 1;
    pub const EPOLL_CTL_DEL: u64 = 2;
    pub const EPOLL_CTL_MOD: u64 = 3;

    pub const EPOLLIN: u32 = 0x001;
    pub const EPOLLPRI: u32 = 0x002;
    pub const EPOLLOUT: u32 = 0x004;
    pub const EPOLLERR: u32 = 0x008;
    pub const EPOLLHUP: u32 = 0x010;
    pub const EPOLLRDHUP: u32 = 0x2000;
    pub const EPOLLONESHOT: u32 = 1 << 30;
    pub const EPOLLET: u32 = 1 << 31;
}

/// Socket constants (Linux `sys/socket.h`, arm64 values). These are the
/// guest-facing numbers; `crates/kernel/src/net.rs` maps them to host values on
/// macOS and passes them through on Linux.
pub mod socket {
    // Address families.
    pub const AF_UNIX: u64 = 1;
    pub const AF_INET: u64 = 2;
    pub const AF_INET6: u64 = 10;

    // Socket types, and the flags Linux packs into the `type` argument.
    pub const SOCK_STREAM: u64 = 1;
    pub const SOCK_DGRAM: u64 = 2;
    pub const SOCK_RAW: u64 = 3;
    pub const SOCK_SEQPACKET: u64 = 5;
    pub const SOCK_TYPE_MASK: u64 = 0xf;
    /// `O_NONBLOCK`.
    pub const SOCK_NONBLOCK: u64 = 0o4000;
    /// `O_CLOEXEC`.
    pub const SOCK_CLOEXEC: u64 = 0o2000000;

    pub const SOL_SOCKET: u64 = 1;

    // `SOL_SOCKET` options.
    pub const SO_REUSEADDR: u64 = 2;
    pub const SO_TYPE: u64 = 3;
    pub const SO_ERROR: u64 = 4;
    pub const SO_DONTROUTE: u64 = 5;
    pub const SO_BROADCAST: u64 = 6;
    pub const SO_SNDBUF: u64 = 7;
    pub const SO_RCVBUF: u64 = 8;
    pub const SO_KEEPALIVE: u64 = 9;
    pub const SO_OOBINLINE: u64 = 10;
    pub const SO_LINGER: u64 = 13;
    pub const SO_REUSEPORT: u64 = 15;
    pub const SO_RCVTIMEO: u64 = 20;
    pub const SO_SNDTIMEO: u64 = 21;
    pub const SO_ACCEPTCONN: u64 = 30;

    // `send`/`recv` flags.
    pub const MSG_OOB: u64 = 0x01;
    pub const MSG_PEEK: u64 = 0x02;
    pub const MSG_DONTROUTE: u64 = 0x04;
    pub const MSG_CTRUNC: u64 = 0x08;
    pub const MSG_TRUNC: u64 = 0x20;
    pub const MSG_DONTWAIT: u64 = 0x40;
    pub const MSG_EOR: u64 = 0x80;
    pub const MSG_WAITALL: u64 = 0x100;
    pub const MSG_NOSIGNAL: u64 = 0x4000;
}

/// `eventfd2` flags (`sys/eventfd.h`).
pub mod eventfd {
    pub const EFD_SEMAPHORE: u64 = 1;
    /// `O_NONBLOCK` on arm64.
    pub const EFD_NONBLOCK: u64 = 0o4000;
    /// `O_CLOEXEC`.
    pub const EFD_CLOEXEC: u64 = 0o2000000;
}

/// `timerfd` flags (`sys/timerfd.h`).
pub mod timerfd {
    /// `O_NONBLOCK` on arm64.
    pub const TFD_NONBLOCK: u64 = 0o4000;
    /// `O_CLOEXEC`.
    pub const TFD_CLOEXEC: u64 = 0o2000000;
    /// `timerfd_settime` flag: `new_value` is an absolute time.
    pub const TFD_TIMER_ABSTIME: u64 = 1;
    pub const TFD_TIMER_CANCEL_ON_SET: u64 = 2;
}

/// `struct itimerspec` (`it_interval`, then `it_value`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Itimerspec {
    pub it_interval: Timespec,
    pub it_value: Timespec,
}

/// `struct epoll_event`. Only x86-64 packs it; on arm64 it is naturally
/// aligned, 16 bytes, with the `data` word at offset 8.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EpollEvent {
    pub events: u32,
    pub data: u64,
}

/// `struct timespec`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

/// `tv_nsec` values `utimensat` takes for "now" and "leave as it is".
pub const UTIME_NOW: i64 = (1 << 30) - 1;
pub const UTIME_OMIT: i64 = (1 << 30) - 2;

/// `struct iovec`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Iovec {
    pub iov_base: u64,
    pub iov_len: u64,
}

/// `struct pollfd`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Pollfd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}

/// `struct flock` (arm64: 64-bit offsets, padded to 32 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Flock {
    pub l_type: i16,
    pub l_whence: i16,
    pub l_start: i64,
    pub l_len: i64,
    pub l_pid: i32,
}

/// `struct winsize`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Winsize {
    pub ws_row: u16,
    pub ws_col: u16,
    pub ws_xpixel: u16,
    pub ws_ypixel: u16,
}

/// `struct rlimit64`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rlimit {
    pub rlim_cur: u64,
    pub rlim_max: u64,
}

/// Length of each field of `struct new_utsname`.
pub const UTSNAME_LEN: usize = 65;

/// `struct sysinfo` (64-bit: the trailing pad array is empty).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Sysinfo {
    pub uptime: i64,
    /// 1, 5 and 15 minute load averages, scaled by `1 << SI_LOAD_SHIFT`.
    pub loads: [u64; 3],
    pub totalram: u64,
    pub freeram: u64,
    pub sharedram: u64,
    pub bufferram: u64,
    pub totalswap: u64,
    pub freeswap: u64,
    pub procs: u16,
    pub pad: u16,
    pub totalhigh: u64,
    pub freehigh: u64,
    pub mem_unit: u32,
}

/// `sysinfo` load averages are fixed point with this many fraction bits.
pub const SI_LOAD_SHIFT: u32 = 16;

/// `struct new_utsname`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Utsname {
    pub sysname: [u8; UTSNAME_LEN],
    pub nodename: [u8; UTSNAME_LEN],
    pub release: [u8; UTSNAME_LEN],
    pub version: [u8; UTSNAME_LEN],
    pub machine: [u8; UTSNAME_LEN],
    pub domainname: [u8; UTSNAME_LEN],
}

/// Kernel `struct sigaction` on arm64 (no `sa_restorer` use, but present).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sigaction {
    pub handler: u64,
    pub flags: u64,
    pub restorer: u64,
    pub mask: u64,
}

/// `stack_t`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stack {
    pub ss_sp: u64,
    pub ss_flags: i32,
    pub _pad: i32,
    pub ss_size: u64,
}

/// Kernel `struct statfs` on arm64 (`asm-generic/statfs.h`, 64-bit words).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Statfs {
    pub f_type: i64,
    pub f_bsize: i64,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_fsid: [i32; 2],
    pub f_namelen: i64,
    pub f_frsize: i64,
    pub f_flags: i64,
    pub f_spare: [i64; 4],
}

/// `memfd_create` flags.
pub mod memfd {
    pub const MFD_CLOEXEC: u64 = 0x1;
    pub const MFD_ALLOW_SEALING: u64 = 0x2;
    pub const MFD_HUGETLB: u64 = 0x4;
    pub const MFD_NOEXEC_SEAL: u64 = 0x8;
    pub const MFD_EXEC: u64 = 0x10;
    /// The longest name, without the `memfd:` prefix Linux adds.
    pub const NAME_MAX: usize = 249;
}

/// `fallocate` modes.
pub mod falloc {
    pub const FALLOC_FL_KEEP_SIZE: u64 = 0x01;
    pub const FALLOC_FL_PUNCH_HOLE: u64 = 0x02;
}

/// `statfs` values: the `f_type` fwe reports for the host filesystems it
/// serves files from, and the `f_flags` mount flags.
pub mod statfs {
    pub const EXT4_SUPER_MAGIC: i64 = 0xef53;
    pub const ST_RDONLY: i64 = 1;
    pub const ST_NOSUID: i64 = 2;
    pub const ST_NODEV: i64 = 4;
    pub const ST_NOEXEC: i64 = 8;
    pub const ST_NOATIME: i64 = 1024;
    pub const ST_NODIRATIME: i64 = 2048;
    pub const ST_RELATIME: i64 = 4096;
    /// `msync` flags.
    pub const MS_ASYNC: u64 = 1;
    pub const MS_INVALIDATE: u64 = 2;
    pub const MS_SYNC: u64 = 4;
}

/// Kernel `struct stat` on arm64 (`asm-generic/stat.h`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_mode: u32,
    pub st_nlink: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_rdev: u64,
    pub __pad1: u64,
    pub st_size: i64,
    pub st_blksize: i32,
    pub __pad2: i32,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: u64,
    pub st_mtime: i64,
    pub st_mtime_nsec: u64,
    pub st_ctime: i64,
    pub st_ctime_nsec: u64,
    pub __unused4: u32,
    pub __unused5: u32,
}

/// `struct statx_timestamp`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StatxTimestamp {
    pub tv_sec: i64,
    pub tv_nsec: u32,
    pub __reserved: i32,
}

/// `struct statx` (`linux/stat.h`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Statx {
    pub stx_mask: u32,
    pub stx_blksize: u32,
    pub stx_attributes: u64,
    pub stx_nlink: u32,
    pub stx_uid: u32,
    pub stx_gid: u32,
    pub stx_mode: u16,
    pub __spare0: u16,
    pub stx_ino: u64,
    pub stx_size: u64,
    pub stx_blocks: u64,
    pub stx_attributes_mask: u64,
    pub stx_atime: StatxTimestamp,
    pub stx_btime: StatxTimestamp,
    pub stx_ctime: StatxTimestamp,
    pub stx_mtime: StatxTimestamp,
    pub stx_rdev_major: u32,
    pub stx_rdev_minor: u32,
    pub stx_dev_major: u32,
    pub stx_dev_minor: u32,
    pub stx_mnt_id: u64,
    pub stx_dio_mem_align: u32,
    pub stx_dio_offset_align: u32,
    pub __spare3: [u64; 12],
}

/// Fixed-size head of `struct linux_dirent64`; the name follows inline.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Dirent64 {
    pub d_ino: u64,
    pub d_off: i64,
    pub d_reclen: u16,
    pub d_type: u8,
}

/// Bytes of a `linux_dirent64` header before the name.
pub const DIRENT64_HEADER: usize = 19;

/// Encode a negative errno as a raw syscall return value.
pub const fn err(errno: i32) -> i64 {
    -(errno as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn generated_tables() {
        assert_eq!(nr::WRITE, 64);
        assert_eq!(nr::EXIT_GROUP, 94);
        assert_eq!(nr::MMAP, 222);
        assert_eq!(nr::CLONE3, 435);
        assert_eq!(syscall_name(nr::OPENAT), Some("openat"));
        assert_eq!(syscall_name(244), None);
        assert_eq!(errno::ENOSYS, 38);
        assert_eq!(errno::EWOULDBLOCK, errno::EAGAIN);
        assert_eq!(errno_name(11), Some("EAGAIN"));
    }

    #[test]
    fn struct_layouts() {
        assert_eq!(size_of::<Timespec>(), 16);
        assert_eq!(size_of::<Iovec>(), 16);
        assert_eq!(size_of::<Pollfd>(), 8);
        assert_eq!(size_of::<EpollEvent>(), 16);
        assert_eq!(size_of::<Itimerspec>(), 32);
        assert_eq!(size_of::<Winsize>(), 8);
        assert_eq!(size_of::<Flock>(), 32);
        assert_eq!(size_of::<Statfs>(), 120);
        assert_eq!(size_of::<Sysinfo>(), 112);
        assert_eq!(core::mem::offset_of!(Sysinfo, totalhigh), 88);
        assert_eq!(size_of::<Rlimit>(), 16);
        assert_eq!(size_of::<Utsname>(), 390);
        assert_eq!(size_of::<Sigaction>(), 32);
        assert_eq!(size_of::<Stack>(), 24);
        assert_eq!(size_of::<Stat>(), 128);
        assert_eq!(size_of::<StatxTimestamp>(), 16);
        assert_eq!(size_of::<Statx>(), 256);
        // The header is packed in the kernel ABI; our struct is naturally
        // aligned, so we serialize its first DIRENT64_HEADER bytes by hand.
        assert_eq!(DIRENT64_HEADER, 19);
    }

    #[test]
    fn errors_are_negative() {
        assert_eq!(err(errno::ENOSYS), -38);
    }
}
