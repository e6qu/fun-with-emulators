//! Memory management system calls.

use crate::host::{last_error, ret};
use crate::{Kernel, Platform};
use fwe_abi::{err, errno, mman};

/// The program break: a reserved region after the executable image that
/// `brk` commits and releases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Brk {
    pub start: u64,
    pub current: u64,
    /// End of the reservation; the break cannot grow past it.
    pub limit: u64,
}

impl Brk {
    /// Default size of the reservation.
    pub const RESERVATION: u64 = 1 << 30;

    /// Reserve `size` bytes of address space at page-aligned `start`.
    ///
    /// If the range is not available the break cannot grow; allocators then
    /// fall back to `mmap`, as they do on Linux when `brk` fails.
    pub fn reserve(start: u64, size: u64) -> Brk {
        match crate::host::reserve_fixed(start, size) {
            Ok(()) => Brk { start, current: start, limit: start + size },
            Err(_) => Brk { start, current: start, limit: start },
        }
    }
}

/// Map anonymous memory at a fixed address, replacing what is there.
fn map_fixed_anon(addr: u64, len: u64, prot: libc::c_int) -> bool {
    // SAFETY: callers only pass ranges owned by the guest.
    let p = unsafe {
        libc::mmap(
            addr as *mut libc::c_void,
            len as usize,
            prot,
            libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED,
            -1,
            0,
        )
    };
    p != libc::MAP_FAILED
}

/// Largest backing file read to find its executable sections.
const MAX_EXEC_FILE: usize = 128 << 20;

/// The executable sections of the ELF file open at `fd`, as file-offset
/// ranges, or `None` if it is not a readable regular ELF with section headers
/// (then the caller translates the whole mapped region instead). Reads with
/// `pread`, so the guest's file position is untouched.
fn exec_file_ranges(fd: i32) -> Option<Vec<(u64, u64)>> {
    if fd < 0 {
        return None;
    }
    // SAFETY: zeroing a stat value, which is plain data.
    let mut st: libc::stat = unsafe { core::mem::zeroed() };
    // SAFETY: fstat on a borrowed fd, writing into the stat just created.
    let fstat_ok = unsafe { libc::fstat(fd, &mut st) } == 0;
    if !fstat_ok || st.st_mode & libc::S_IFMT != libc::S_IFREG {
        return None;
    }
    let size = st.st_size as usize;
    if !(64..=MAX_EXEC_FILE).contains(&size) {
        return None;
    }
    let mut buf = vec![0u8; size];
    let mut done = 0usize;
    while done < size {
        // SAFETY: pread into the owned buffer at an explicit offset.
        let n = unsafe {
            libc::pread(
                fd,
                buf[done..].as_mut_ptr() as *mut libc::c_void,
                size - done,
                done as libc::off_t,
            )
        };
        if n <= 0 {
            return None;
        }
        done += n as usize;
    }
    fwe_elf::Elf::parse(&buf).ok()?.exec_file_ranges()
}

fn host_prot(prot: u64) -> libc::c_int {
    let mut p = libc::PROT_NONE;
    if prot & mman::PROT_READ != 0 {
        p |= libc::PROT_READ;
    }
    if prot & mman::PROT_WRITE != 0 {
        p |= libc::PROT_WRITE;
    }
    if prot & mman::PROT_EXEC != 0 {
        p |= libc::PROT_EXEC;
    }
    p
}

impl<P: Platform> Kernel<P> {
    fn page_up(&self, a: u64) -> u64 {
        (a + self.page_size - 1) & !(self.page_size - 1)
    }

    pub(crate) fn sys_brk(&mut self, addr: u64) -> i64 {
        let b = self.brk;
        if addr < b.start || addr > b.limit {
            return b.current as i64;
        }
        let old_end = self.page_up(b.current);
        let new_end = self.page_up(addr);
        let ok = if new_end > old_end {
            map_fixed_anon(old_end, new_end - old_end, libc::PROT_READ | libc::PROT_WRITE)
        } else if new_end < old_end {
            // Released pages must read as zero if the break grows again.
            map_fixed_anon(new_end, old_end - new_end, libc::PROT_NONE)
        } else {
            true
        };
        if ok {
            self.brk.current = addr;
        }
        self.brk.current as i64
    }

    pub(crate) fn sys_mmap(
        &mut self,
        addr: u64,
        len: u64,
        prot: u64,
        flags: u64,
        fd: u64,
        offset: u64,
    ) -> i64 {
        if len == 0 || offset & (self.page_size - 1) != 0 {
            return err(errno::EINVAL);
        }
        let anonymous = flags & mman::MAP_ANONYMOUS != 0;
        let mut hflags = match flags & mman::MAP_TYPE {
            mman::MAP_SHARED | mman::MAP_SHARED_VALIDATE => libc::MAP_SHARED,
            mman::MAP_PRIVATE => libc::MAP_PRIVATE,
            _ => return err(errno::EINVAL),
        };
        if anonymous {
            hflags |= libc::MAP_ANON;
        }
        if flags & mman::MAP_FIXED != 0 {
            hflags |= libc::MAP_FIXED;
        }
        if flags & mman::MAP_NORESERVE != 0 {
            hflags |= libc::MAP_NORESERVE;
        }
        let noreplace = flags & mman::MAP_FIXED_NOREPLACE != 0 && flags & mman::MAP_FIXED == 0;

        // Executable mappings are created writable so the backend can prepare
        // the code, then switched to the requested protections. Shared file
        // mappings are made private for this, since the code is modified.
        let exec = prot & mman::PROT_EXEC != 0;
        let initial_prot = if exec {
            if hflags & libc::MAP_SHARED != 0 && !anonymous {
                hflags = (hflags & !libc::MAP_SHARED) | libc::MAP_PRIVATE;
            }
            libc::PROT_READ | libc::PROT_WRITE
        } else {
            host_prot(prot)
        };

        let host_fd = if anonymous { -1 } else { fd as i32 };
        // SAFETY: guest-requested mapping. MAP_FIXED may replace guest memory,
        // which is the guest's own business, exactly as on Linux.
        let p = unsafe {
            libc::mmap(
                addr as *mut libc::c_void,
                len as usize,
                initial_prot,
                hflags,
                host_fd,
                offset as libc::off_t,
            )
        };
        if p == libc::MAP_FAILED {
            return last_error();
        }
        let p = p as u64;
        if noreplace && p != addr {
            // SAFETY: unmapping the mapping just created.
            unsafe { libc::munmap(p as *mut libc::c_void, len as usize) };
            return err(errno::EEXIST);
        }
        if exec {
            // Translate the code. For a file-backed mapping, confine the
            // rewrite to the file's executable sections, so data mapped into
            // the same region — the symbol, string and hash tables that a
            // shared library's code segment can hold, as glibc's `libc.so.6`
            // does — is left untouched. Without section headers, or for an
            // anonymous mapping, the whole region is translated as before.
            let prep = match if anonymous { None } else { exec_file_ranges(host_fd) } {
                Some(sections) => sections
                    .into_iter()
                    .filter_map(|(foff, fsize)| {
                        let start = foff.max(offset);
                        let end = (foff + fsize).min(offset + len);
                        (start < end).then_some((p + (start - offset), end - start))
                    })
                    .collect(),
                None => vec![(p, self.page_up(len))],
            };
            for (a, l) in prep {
                if let Err(e) = self.platform.prepare_exec(a, l) {
                    // SAFETY: unmapping the mapping just created.
                    unsafe { libc::munmap(p as *mut libc::c_void, len as usize) };
                    return err(e);
                }
            }
            // SAFETY: changing protections of the mapping just created.
            if unsafe { libc::mprotect(p as *mut libc::c_void, len as usize, host_prot(prot)) } != 0
            {
                let e = last_error();
                // SAFETY: unmapping the mapping just created.
                unsafe { libc::munmap(p as *mut libc::c_void, len as usize) };
                return e;
            }
        }
        p as i64
    }

    pub(crate) fn sys_munmap(&mut self, addr: u64, len: u64) -> i64 {
        // SAFETY: guest-requested unmapping of guest memory.
        ret(unsafe { libc::munmap(addr as *mut libc::c_void, len as usize) })
    }

    pub(crate) fn sys_mprotect(&mut self, addr: u64, len: u64, prot: u64) -> i64 {
        let a = addr as *mut libc::c_void;
        if prot & mman::PROT_EXEC != 0 {
            // SAFETY: guest-requested protection change of guest memory.
            if unsafe { libc::mprotect(a, len as usize, libc::PROT_READ | libc::PROT_WRITE) } != 0 {
                return last_error();
            }
            if let Err(e) = self.platform.prepare_exec(addr, self.page_up(len)) {
                return err(e);
            }
        }
        // SAFETY: guest-requested protection change of guest memory.
        ret(unsafe { libc::mprotect(a, len as usize, host_prot(prot)) })
    }

    pub(crate) fn sys_madvise(&mut self, addr: u64, len: u64, advice: u64) -> i64 {
        if addr & (self.page_size - 1) != 0 {
            return err(errno::EINVAL);
        }
        let len = self.page_up(len);
        match advice {
            // Linux guarantees zero-filled pages on the next access to private
            // anonymous memory; macOS's MADV_DONTNEED does not, so replace
            // the pages instead.
            mman::MADV_DONTNEED => {
                if map_fixed_anon(addr, len, libc::PROT_READ | libc::PROT_WRITE) {
                    0
                } else {
                    last_error()
                }
            }
            mman::MADV_FREE => {
                // SAFETY: advisory call on guest memory.
                unsafe { libc::madvise(addr as *mut libc::c_void, len as usize, libc::MADV_FREE) };
                0
            }
            mman::MADV_NORMAL | mman::MADV_RANDOM | mman::MADV_SEQUENTIAL | mman::MADV_WILLNEED => {
                // SAFETY: advisory call on guest memory; values match the host's.
                ret(unsafe {
                    libc::madvise(addr as *mut libc::c_void, len as usize, advice as libc::c_int)
                })
            }
            // Other advice (huge pages, dump control, ...) has no host
            // equivalent and no effect on program semantics.
            _ => 0,
        }
    }

    pub(crate) fn sys_mremap(&mut self, old: u64, old_len: u64, new_len: u64, flags: u64) -> i64 {
        if old & (self.page_size - 1) != 0 || new_len == 0 {
            return err(errno::EINVAL);
        }
        let old_len = self.page_up(old_len);
        let new_len = self.page_up(new_len);
        if new_len <= old_len {
            if new_len < old_len {
                // SAFETY: unmapping the tail of a guest mapping.
                unsafe {
                    libc::munmap((old + new_len) as *mut libc::c_void, (old_len - new_len) as usize)
                };
            }
            return old as i64;
        }
        if flags & mman::MREMAP_MAYMOVE == 0 {
            // Cannot grow in place yet. Like Linux, report EFAULT for an
            // unmapped source range and ENOMEM otherwise.
            // SAFETY: msync only inspects the mapping state of the range.
            let mapped =
                unsafe { libc::msync(old as *mut libc::c_void, old_len as usize, libc::MS_ASYNC) }
                    == 0;
            return err(if mapped { errno::ENOMEM } else { errno::EFAULT });
        }
        err(errno::ENOMEM)
    }
}
