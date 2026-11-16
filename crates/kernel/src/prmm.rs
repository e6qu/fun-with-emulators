//! `prctl(PR_SET_MM)`: the layout of a process's memory the kernel keeps
//! (where its code, data, break, stack, arguments and environment are),
//! its auxiliary vector and its program file, as checkpoint/restore tools
//! set them and programs that rename themselves set the arguments' range.
//!
//! The layout starts as the program was loaded: its image's code and data
//! from the mappings, the break, and the argument and environment strings
//! the auxiliary vector places. A change is checked as Linux checks it
//! (`validate_prctl_map_addr`) and kept; a new argument range is what
//! `/proc/<pid>/cmdline` shows from then on (as the memory holds it at the
//! change), a new environment range what `/proc/self/environ` reads, a new
//! auxiliary vector what `/proc/<pid>/auxv` shows, and a new program file
//! what `/proc/<pid>/exe` names. The break's start and end are kept in the
//! layout; the break itself stays where `brk` keeps it.

use crate::{Kernel, Platform, uaccess};
use fwe_abi::{err, errno};
use std::sync::Mutex;

/// `PR_SET_MM` and its options.
pub const PR_SET_MM: u64 = 35;
pub const PR_SET_MM_START_CODE: u64 = 1;
pub const PR_SET_MM_END_CODE: u64 = 2;
pub const PR_SET_MM_START_DATA: u64 = 3;
pub const PR_SET_MM_END_DATA: u64 = 4;
pub const PR_SET_MM_START_STACK: u64 = 5;
pub const PR_SET_MM_START_BRK: u64 = 6;
pub const PR_SET_MM_BRK: u64 = 7;
pub const PR_SET_MM_ARG_START: u64 = 8;
pub const PR_SET_MM_ARG_END: u64 = 9;
pub const PR_SET_MM_ENV_START: u64 = 10;
pub const PR_SET_MM_ENV_END: u64 = 11;
pub const PR_SET_MM_AUXV: u64 = 12;
pub const PR_SET_MM_EXE_FILE: u64 = 13;
pub const PR_SET_MM_MAP: u64 = 14;
pub const PR_SET_MM_MAP_SIZE: u64 = 15;

/// `sizeof(struct prctl_mm_map)`: eleven addresses, the auxiliary
/// vector's address, its size and the program's descriptor.
pub const MM_MAP_SIZE: usize = 104;
/// `sizeof(mm->saved_auxv)` on arm64: `AT_VECTOR_SIZE` words,
/// `2 * (AT_VECTOR_SIZE_ARCH + AT_VECTOR_SIZE_BASE + 1)` with 2 and 22.
pub const SAVED_AUXV: usize = 50 * 8;
/// `TASK_SIZE` with 48-bit addresses.
const TASK_SIZE: u64 = 1 << 48;

/// The layout, in `struct prctl_mm_map`'s order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Layout {
    pub start_code: u64,
    pub end_code: u64,
    pub start_data: u64,
    pub end_data: u64,
    pub start_brk: u64,
    pub brk: u64,
    pub start_stack: u64,
    pub arg_start: u64,
    pub arg_end: u64,
    pub env_start: u64,
    pub env_end: u64,
}

impl Layout {
    fn fields(&self) -> [u64; 11] {
        [
            self.start_code,
            self.end_code,
            self.start_data,
            self.end_data,
            self.start_brk,
            self.brk,
            self.start_stack,
            self.arg_start,
            self.arg_end,
            self.env_start,
            self.env_end,
        ]
    }

    fn from_fields(f: &[u64]) -> Layout {
        Layout {
            start_code: f[0],
            end_code: f[1],
            start_data: f[2],
            end_data: f[3],
            start_brk: f[4],
            brk: f[5],
            start_stack: f[6],
            arg_start: f[7],
            arg_end: f[8],
            env_start: f[9],
            env_end: f[10],
        }
    }

    /// Linux's `validate_prctl_map_addr`, with `RLIMIT_DATA` `data_limit`:
    /// every address within the space a mapping may use, the pairs in
    /// order (`EINVAL`), and the break and data within the limit.
    pub fn validate(&self, data_limit: u64) -> Result<(), i32> {
        let min = crate::mm::MMAP_MIN_ADDR;
        if self.fields().iter().any(|&v| v >= TASK_SIZE || v < min) {
            return Err(errno::EINVAL);
        }
        if self.start_code >= self.end_code
            || self.start_data > self.end_data
            || self.start_brk > self.brk
            || self.arg_start > self.arg_end
            || self.env_start > self.env_end
        {
            return Err(errno::EINVAL);
        }
        // `check_data_rlimit`.
        let used = (self.brk - self.start_brk).saturating_add(self.end_data - self.start_data);
        if data_limit != u64::MAX && used > data_limit {
            return Err(errno::EINVAL);
        }
        Ok(())
    }
}

/// The layout as changed since the program started (`None`: as it was
/// loaded, worked out when asked).
static LAYOUT: Mutex<Option<Layout>> = Mutex::new(None);
/// The environment's range, once `PR_SET_MM` has moved it.
static ENV_MOVED: Mutex<Option<(u64, u64)>> = Mutex::new(None);

/// A new program runs: its layout is the one it was loaded with.
pub fn reset() {
    *LAYOUT.lock().unwrap_or_else(|e| e.into_inner()) = None;
    *ENV_MOVED.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

/// The environment's range, if `PR_SET_MM` moved it.
pub fn env_moved() -> Option<(u64, u64)> {
    *ENV_MOVED.lock().unwrap_or_else(|e| e.into_inner())
}

/// Linux's `get_mm_cmdline` over memory read by `read`: the arguments
/// `[arg_start, arg_end)`; if their last byte is no longer a NUL (the
/// program wrote a longer title over them, as `setproctitle` does), the
/// text up to the first NUL, through the environment up to `env_end`.
pub fn cmdline(l: &Layout, read: impl Fn(u64, &mut [u8]) -> bool) -> Vec<u8> {
    const MAX: u64 = 4 << 20;
    if l.arg_end <= l.arg_start || l.arg_end - l.arg_start > MAX {
        return Vec::new();
    }
    let mut b = vec![0u8; (l.arg_end - l.arg_start) as usize];
    if !read(l.arg_start, &mut b) {
        return Vec::new();
    }
    if b.last() == Some(&0) {
        return b;
    }
    if l.env_end > l.arg_end && l.env_end - l.arg_end <= MAX {
        let mut more = vec![0u8; (l.env_end - l.arg_end) as usize];
        if read(l.arg_end, &mut more) {
            b.extend_from_slice(&more);
        }
    }
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    b.truncate(end);
    b
}

/// `auxv` (words, ending at the first `AT_NULL`) as `mm->saved_auxv`'s
/// bytes: padded with zeros.
fn saved(auxv: &[u8]) -> Vec<u8> {
    let mut s = auxv.to_vec();
    s.resize(SAVED_AUXV, 0);
    s
}

/// The vector `/proc/<pid>/auxv` shows of `saved` bytes: its pairs up to
/// and with the first `AT_NULL`, the last pair always one.
fn shown(saved: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for pair in saved.chunks(16).take(SAVED_AUXV / 16 - 1) {
        out.extend_from_slice(pair);
        if pair[..8] == [0; 8] {
            return out;
        }
    }
    out.extend_from_slice(&[0; 16]);
    out
}

impl<P: Platform> Kernel<P> {
    /// The layout now: as changed, or as the program was loaded.
    fn layout(&self) -> Layout {
        if let Some(l) = *LAYOUT.lock().unwrap_or_else(|e| e.into_inner()) {
            return l;
        }
        let mut l = Layout::default();
        let record = crate::maps::record();
        let areas = record.areas();
        let image = areas.iter().filter(|p| p.value.object.name == crate::maps::Name::Exe);
        for p in image {
            if p.value.prot & fwe_abi::mman::PROT_EXEC != 0 {
                if l.start_code == 0 {
                    (l.start_code, l.end_code) = (p.start, p.end);
                }
            } else if p.value.prot & fwe_abi::mman::PROT_WRITE != 0 && l.start_data == 0 {
                (l.start_data, l.end_data) = (p.start, p.end);
            }
        }
        drop(record);
        (l.start_brk, l.brk) = (self.brk.start, self.brk.current);
        let auxv = self.fs_opt().map(|f| f.auxv().to_vec()).unwrap_or_default();
        let cmdline_len = self.fs_opt().map_or(0, |f| f.proc_cmdline().len() as u64);
        let at = |k| crate::procfs::auxv_value(&auxv, k).unwrap_or(0);
        // The strings follow the platform's name ("aarch64" and its NUL)
        // and end with the program's name.
        let platform = at(fwe_abi::auxv::AT_PLATFORM);
        if platform != 0 {
            l.start_stack = platform & !15;
            l.arg_start = platform + 8;
            l.arg_end = l.arg_start + cmdline_len;
            l.env_start = l.arg_end;
            l.env_end = at(fwe_abi::auxv::AT_EXECFN).max(l.env_start);
        }
        l
    }

    /// `prctl(PR_SET_MM, opt, addr, arg4, arg5)`, in Linux's order.
    pub(crate) fn prctl_set_mm(&mut self, opt: u64, addr: u64, arg4: u64, arg5: u64) -> i64 {
        if arg5 != 0
            || (arg4 != 0 && !matches!(opt, PR_SET_MM_AUXV | PR_SET_MM_MAP | PR_SET_MM_MAP_SIZE))
        {
            return err(errno::EINVAL);
        }
        match opt {
            PR_SET_MM_MAP_SIZE => {
                crate::guest!(uaccess::write(addr, MM_MAP_SIZE as u32));
                return 0;
            }
            PR_SET_MM_MAP => return self.set_mm_map(addr, arg4).map_or_else(err, |()| 0),
            _ => {}
        }
        if !self.creds.has(crate::caps::CAP_SYS_RESOURCE) {
            return err(errno::EPERM);
        }
        match opt {
            PR_SET_MM_EXE_FILE => {
                return self.set_exe_file(addr as u32 as i32).map_or_else(err, |()| 0);
            }
            PR_SET_MM_AUXV => return self.set_auxv(addr, arg4).map_or_else(err, |()| 0),
            _ => {}
        }
        if !(crate::mm::MMAP_MIN_ADDR..TASK_SIZE).contains(&addr) {
            return err(errno::EINVAL);
        }
        let mut l = self.layout();
        let old = l;
        match opt {
            PR_SET_MM_START_CODE => l.start_code = addr,
            PR_SET_MM_END_CODE => l.end_code = addr,
            PR_SET_MM_START_DATA => l.start_data = addr,
            PR_SET_MM_END_DATA => l.end_data = addr,
            PR_SET_MM_START_STACK => l.start_stack = addr,
            PR_SET_MM_START_BRK => l.start_brk = addr,
            PR_SET_MM_BRK => l.brk = addr,
            PR_SET_MM_ARG_START => l.arg_start = addr,
            PR_SET_MM_ARG_END => l.arg_end = addr,
            PR_SET_MM_ENV_START => l.env_start = addr,
            PR_SET_MM_ENV_END => l.env_end = addr,
            _ => return err(errno::EINVAL),
        }
        let limit = crate::syscalls::own_limit_of(fwe_abi::resource::RLIMIT_DATA);
        if let Err(e) = l.validate(limit) {
            return err(e);
        }
        // An address on the stack or among the strings must have a
        // mapping at or above it (`find_vma`).
        if matches!(opt, PR_SET_MM_START_STACK..=PR_SET_MM_ENV_END)
            && !matches!(opt, PR_SET_MM_START_BRK | PR_SET_MM_BRK)
            && !crate::maps::record().areas().iter().any(|p| p.end > addr)
        {
            return err(errno::EFAULT);
        }
        self.keep_layout(l, old);
        0
    }

    /// Make `l` the layout (it was `old`), with what it changes.
    fn keep_layout(&mut self, l: Layout, old: Layout) {
        *LAYOUT.lock().unwrap_or_else(|e| e.into_inner()) = Some(l);
        if (l.env_start, l.env_end) != (old.env_start, old.env_end) {
            *ENV_MOVED.lock().unwrap_or_else(|e| e.into_inner()) = Some((l.env_start, l.env_end));
        }
        if (l.arg_start, l.arg_end) != (old.arg_start, old.arg_end) {
            let text = cmdline(&l, |a, b| uaccess::read_into(a, b).is_ok());
            if let Some(fs) = self.fs_opt_mut() {
                fs.set_proc_cmdline(text);
            }
        }
    }

    /// `PR_SET_MM_MAP`: the whole layout, and with it the auxiliary vector
    /// and the program file, from a `struct prctl_mm_map` at `addr` of
    /// `size` bytes. Linux's `prctl_set_mm_map`: no capability, but
    /// `CAP_CHECKPOINT_RESTORE` (or `CAP_SYS_ADMIN`) for the program file.
    fn set_mm_map(&mut self, addr: u64, size: u64) -> Result<(), i32> {
        if size != MM_MAP_SIZE as u64 {
            return Err(errno::EINVAL);
        }
        let raw = uaccess::read_bytes(addr, MM_MAP_SIZE).map_err(|_| errno::EFAULT)?;
        let word = |i: usize| u64::from_le_bytes(raw[i * 8..i * 8 + 8].try_into().unwrap());
        let fields: Vec<u64> = (0..11).map(word).collect();
        let l = Layout::from_fields(&fields);
        l.validate(crate::syscalls::own_limit_of(fwe_abi::resource::RLIMIT_DATA))?;
        let auxv_at = word(11);
        let auxv_size = u32::from_le_bytes(raw[96..100].try_into().unwrap()) as usize;
        let exe_fd = u32::from_le_bytes(raw[100..104].try_into().unwrap());
        let auxv = if auxv_size != 0 {
            if auxv_at == 0 || auxv_size > SAVED_AUXV {
                return Err(errno::EINVAL);
            }
            let mut a = uaccess::read_bytes(auxv_at, auxv_size).map_err(|_| errno::EFAULT)?;
            a.resize(SAVED_AUXV, 0);
            a[SAVED_AUXV - 16..].fill(0);
            Some(a)
        } else {
            None
        };
        if exe_fd != u32::MAX {
            let own = crate::userns::own_dir();
            if !self.creds.has_in(&own, crate::caps::CAP_CHECKPOINT_RESTORE)
                && !self.creds.has_in(&own, crate::caps::CAP_SYS_ADMIN)
            {
                return Err(errno::EPERM);
            }
            self.set_exe_file(exe_fd as i32)?;
        }
        let old = self.layout();
        self.keep_layout(l, old);
        if let Some(a) = auxv
            && let Some(fs) = self.fs_opt_mut()
        {
            fs.set_auxv(shown(&a));
        }
        Ok(())
    }

    /// `PR_SET_MM_AUXV`: the first `len` bytes of the saved vector from
    /// `addr`, the last pair kept `AT_NULL` (Linux's `prctl_set_auxv`).
    fn set_auxv(&mut self, addr: u64, len: u64) -> Result<(), i32> {
        if len > SAVED_AUXV as u64 {
            return Err(errno::EINVAL);
        }
        let mut new = uaccess::read_bytes(addr, len as usize).map_err(|_| errno::EFAULT)?;
        let len = len as usize;
        if len > SAVED_AUXV - 16 {
            new[SAVED_AUXV - 16..].fill(0);
        }
        let Some(fs) = self.fs_opt_mut() else { return Ok(()) };
        let mut s = saved(fs.auxv());
        s[..len].copy_from_slice(&new);
        fs.set_auxv(shown(&s));
        Ok(())
    }

    /// `PR_SET_MM_EXE_FILE`: the program file is the one open as `fd`, a
    /// regular file the caller may run, on a mount that runs programs
    /// (`EACCES`), not open for writing (`EACCES`), and only once the old
    /// program is no longer mapped (`EBUSY`), as Linux's
    /// `prctl_set_mm_exe_file`.
    fn set_exe_file(&mut self, fd: i32) -> Result<(), i32> {
        let st = crate::fs::guest_stat(fd).ok_or(errno::EBADF)?;
        let noexec =
            crate::fdmarks::origin(fd).is_some_and(|o| o.flags & crate::mounts::ms::NOEXEC != 0);
        if st.st_mode & libc::S_IFMT != libc::S_IFREG || noexec || !self.permits(&st, 1) {
            return Err(errno::EACCES);
        }
        let mapped = crate::maps::record()
            .areas()
            .iter()
            .any(|p| p.value.object.name == crate::maps::Name::Exe);
        if mapped {
            return Err(errno::EBUSY);
        }
        // SAFETY: a valid out-parameter for the guest's descriptor.
        let mut host: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        if unsafe { libc::fstat(fd, &mut host) } == 0 && crate::host_file_busy(&host) {
            return Err(errno::EACCES);
        }
        let Some(fs) = self.fs_opt_mut() else { return Ok(()) };
        let path = fs.fd_target(fd);
        fs.set_proc_exe(path);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout() -> Layout {
        Layout {
            start_code: 0x40_0000,
            end_code: 0x40_8000,
            start_data: 0x41_0000,
            end_data: 0x41_4000,
            start_brk: 0x50_0000,
            brk: 0x50_0000,
            start_stack: 0x7f_0000,
            arg_start: 0x7f_1000,
            arg_end: 0x7f_1010,
            env_start: 0x7f_1010,
            env_end: 0x7f_1100,
        }
    }

    /// A layout is checked as Linux's `validate_prctl_map_addr` checks it.
    #[test]
    fn layouts_are_validated_as_linux_validates_them() {
        let l = layout();
        assert_eq!(l.validate(u64::MAX), Ok(()));
        assert_eq!(Layout { start_code: 0x1000, ..l }.validate(u64::MAX), Err(errno::EINVAL));
        assert_eq!(Layout { env_end: TASK_SIZE, ..l }.validate(u64::MAX), Err(errno::EINVAL));
        assert_eq!(Layout { end_code: l.start_code, ..l }.validate(u64::MAX), Err(errno::EINVAL));
        assert_eq!(Layout { arg_end: l.arg_start, ..l }.validate(u64::MAX), Ok(()));
        assert_eq!(Layout { arg_end: l.arg_start - 1, ..l }.validate(u64::MAX), Err(errno::EINVAL));
        // The data and the break within `RLIMIT_DATA`.
        assert_eq!(l.validate(0x4000), Ok(()));
        assert_eq!(Layout { brk: l.brk + 1, ..l }.validate(0x4000), Err(errno::EINVAL));
        assert_eq!(Layout::from_fields(&l.fields()), l);
    }

    /// The command line is the arguments' range, or with its last NUL
    /// written over, the text up to the first NUL into the environment.
    #[test]
    fn command_lines_are_read_as_linux_reads_them() {
        let mem = b"prog\0arg\0HOME=/\0".to_vec();
        let base = 0x10_0000u64;
        let read = |a: u64, b: &mut [u8]| {
            let at = (a - base) as usize;
            b.copy_from_slice(&mem[at..at + b.len()]);
            true
        };
        let l = Layout {
            arg_start: base,
            arg_end: base + 9,
            env_start: base + 9,
            env_end: base + 16,
            ..layout()
        };
        assert_eq!(cmdline(&l, read), b"prog\0arg\0");
        let titled = b"a long title\0/\0".to_vec();
        let read = |a: u64, b: &mut [u8]| {
            let at = (a - base) as usize;
            b.copy_from_slice(&titled[at..at + b.len()]);
            true
        };
        let l = Layout { env_end: base + 15, ..l };
        assert_eq!(cmdline(&l, read), b"a long title");
    }

    /// A saved vector shows its pairs up to its first `AT_NULL`.
    #[test]
    fn saved_vectors_show_to_their_end() {
        let mut v = vec![6u8, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0];
        v.extend_from_slice(&[0; 16]);
        assert_eq!(shown(&saved(&v)), v);
        let full = vec![1u8; SAVED_AUXV];
        let s = shown(&full);
        assert_eq!(s.len(), SAVED_AUXV);
        assert_eq!(&s[SAVED_AUXV - 16..], &[0; 16]);
    }
}
