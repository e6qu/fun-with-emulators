//! `/proc/self/mem` and `/proc/self/pagemap`: the process's own memory,
//! read and written by address (the file position), and an entry of eight
//! bytes per page telling whether the page is in memory.
//!
//! A descriptor of either is a host file of nothing that fwe marks
//! ([`crate::fdmarks::Mark::Mem`], [`crate::fdmarks::Mark::Pagemap`]);
//! the host keeps its position, and fwe answers its reads and writes. As
//! Linux's, `mem` reaches memory the process may not write itself: a
//! write to private memory that is read-only (a program's code, a private
//! file mapping) goes in, the page made writable only for it, and never
//! reaches the file mapped; read-only shared memory is not written (`EIO`),
//! nor is memory not mapped. A `pagemap` entry has bit 63 if the page is
//! in memory, bit 61 if it is a file's or shared, bit 56 if it is in
//! memory and private; the frame number, which Linux gives only to
//! `CAP_SYS_ADMIN`, is 0. Another process's memory is not reached: macOS
//! gives no process another's.

use crate::fdmarks::{self, Mark};
use crate::uaccess;
use fwe_abi::{err, errno};

const PM_PRESENT: u64 = 1 << 63;
const PM_FILE: u64 = 1 << 61;
const PM_EXCLUSIVE: u64 = 1 << 56;

/// The memory file (`pagemap` if `pagemap`) was opened as `fd`.
pub fn opened(fd: i32, pagemap: bool) {
    fdmarks::mark(fd, if pagemap { Mark::Pagemap } else { Mark::Mem });
}

/// A read or write of descriptor `a[0]` (call `nr`), if it is a memory
/// file: `None` for another descriptor.
pub fn io(nr: u64, a: &[u64; 6]) -> Option<i64> {
    use fwe_abi::nr as n;
    if !matches!(nr, n::READ | n::WRITE | n::PREAD64 | n::PWRITE64) || !fdmarks::any_marks() {
        return None;
    }
    let pagemap = match fdmarks::marked(a[0] as i32)? {
        Mark::Mem => false,
        Mark::Pagemap => true,
        _ => return None,
    };
    let fd = a[0] as i32;
    let write = matches!(nr, n::WRITE | n::PWRITE64);
    // The descriptor must be open for it, as the host knows.
    // SAFETY: F_GETFL only queries the descriptor.
    let mode = unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_ACCMODE;
    if mode < 0 {
        return Some(crate::host::last_error());
    }
    if (write && mode == libc::O_RDONLY) || (!write && mode == libc::O_WRONLY) {
        return Some(err(errno::EBADF));
    }
    let positioned = matches!(nr, n::PREAD64 | n::PWRITE64);
    let pos = if positioned {
        a[3]
    } else {
        // SAFETY: plain host call on the guest's descriptor.
        let p = unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) };
        if p < 0 {
            return Some(crate::host::last_error());
        }
        p as u64
    };
    let (buf, len) = (a[1], a[2].min(1 << 30));
    let r = match (pagemap, write) {
        (true, true) => Err(errno::EINVAL),
        (true, false) => read_pagemap(pos, buf, len),
        (false, false) => read_mem(pos, buf, len),
        (false, true) => write_mem(pos, buf, len),
    };
    Some(match r {
        Ok(done) => {
            if !positioned && done > 0 {
                // SAFETY: plain host call on the guest's descriptor.
                unsafe { libc::lseek(fd, (pos + done) as libc::off_t, libc::SEEK_SET) };
            }
            done as i64
        }
        Err(e) => err(e),
    })
}

/// The part of `[at, at + len)` within the page `at` is in.
fn in_page(at: u64, len: u64) -> u64 {
    let page = crate::maps::page_size();
    len.min(page - at % page)
}

/// Read `len` bytes of memory at `addr` into the guest buffer `buf`: as
/// much as can be read in a row, `EIO` if none can.
fn read_mem(addr: u64, buf: u64, len: u64) -> Result<u64, i32> {
    let mut done = 0;
    let mut chunk = vec![0u8; crate::maps::page_size() as usize];
    while done < len {
        let at = addr.wrapping_add(done);
        let n = in_page(at, len - done);
        let part = &mut chunk[..n as usize];
        if !mapped(at) || uaccess::read_into(at, part).is_err() {
            break;
        }
        uaccess::write_from(buf + done, part)?;
        done += n;
    }
    if done == 0 && len > 0 { Err(errno::EIO) } else { Ok(done) }
}

/// Write `len` bytes from the guest buffer `buf` to memory at `addr`: as
/// much as can be written in a row, `EIO` if none can.
fn write_mem(addr: u64, buf: u64, len: u64) -> Result<u64, i32> {
    let mut done = 0;
    while done < len {
        let at = addr.wrapping_add(done);
        let n = in_page(at, len - done);
        let data = uaccess::read_bytes(buf + done, n as usize)?;
        if !force_write(at, &data) {
            break;
        }
        done += n;
    }
    if done == 0 && len > 0 { Err(errno::EIO) } else { Ok(done) }
}

/// Whether guest address `addr` is in a mapping of the process's.
fn mapped(addr: u64) -> bool {
    !crate::maps::record().areas_in(addr, addr.saturating_add(1)).is_empty()
}

/// Write `data` to guest address `addr`, within one page, as Linux's
/// forced write does: whether it was written.
fn force_write(addr: u64, data: &[u8]) -> bool {
    use fwe_abi::mman::{PROT_EXEC, PROT_WRITE};
    let area = match crate::maps::record().areas_in(addr, addr.saturating_add(1)).first() {
        Some(p) => p.value.clone(),
        None => return false,
    };
    if area.prot & PROT_WRITE != 0 && area.prot & PROT_EXEC == 0 {
        return uaccess::write_from(addr, data).is_ok();
    }
    // Read-only shared memory stays as it is.
    if area.shared && area.prot & PROT_WRITE == 0 {
        return false;
    }
    // Private memory, or code: the host page made writable for the write
    // (a copy of its own, for a file's; not executable meanwhile, which
    // the host allows no page at once), its instructions fetched afresh,
    // then given its protection back.
    let host_page_size = crate::mm::host_page_size();
    let host = uaccess::g2h(addr);
    let page = host & !(host_page_size - 1);
    let prot = crate::mm::host_prot_at(page);
    let writable = (prot & !libc::PROT_EXEC) | libc::PROT_WRITE | libc::PROT_READ;
    // SAFETY: the process's own private memory, given back its protection.
    unsafe {
        if libc::mprotect(page as *mut libc::c_void, host_page_size as usize, writable) != 0 {
            return false;
        }
    }
    let r = uaccess::write_from(addr, data).is_ok();
    if prot & libc::PROT_EXEC != 0 {
        flush_icache(host, data.len());
    }
    // SAFETY: as above.
    unsafe { libc::mprotect(page as *mut libc::c_void, host_page_size as usize, prot) };
    r
}

/// Make the processor fetch the `len` bytes of code at host `addr` afresh.
fn flush_icache(addr: u64, len: usize) {
    #[cfg(target_os = "macos")]
    {
        unsafe extern "C" {
            fn sys_icache_invalidate(start: *mut libc::c_void, len: libc::size_t);
        }
        // SAFETY: the process's own mapped memory.
        unsafe { sys_icache_invalidate(addr as *mut libc::c_void, len) };
    }
    #[cfg(not(target_os = "macos"))]
    let _ = (addr, len);
}

/// Read `len` bytes of `pagemap` at `pos` into the guest buffer `buf`:
/// whole entries only (`EINVAL` otherwise, as Linux's).
fn read_pagemap(pos: u64, buf: u64, len: u64) -> Result<u64, i32> {
    if pos % 8 != 0 || len % 8 != 0 {
        return Err(errno::EINVAL);
    }
    // An entry per guest page, at most those of the address space.
    let page = crate::maps::page_size();
    let first = pos / 8;
    let last = (first + len / 8).min((1 << 48) / page);
    if first >= last {
        return Ok(0);
    }
    let (start, end) = (first * page, last * page);
    let mut entries = vec![0u64; (last - first) as usize];
    let areas = crate::maps::record().areas_in(start, end);
    let host_page_size = crate::mm::host_page_size();
    for p in &areas {
        let (from, to) = (p.start.max(start), p.end.min(end));
        let file = p.value.shared
            || matches!(p.value.object.name, crate::maps::Name::Exe | crate::maps::Name::Path(_));
        // Which host pages are in memory, for the whole stretch at once.
        let host_from = uaccess::g2h(from) & !(host_page_size - 1);
        let host_to = uaccess::g2h(to - 1) + 1;
        let pages = (host_to - host_from).div_ceil(host_page_size) as usize;
        let mut resident = vec![0 as libc::c_char; pages];
        // SAFETY: a range of the process's own mappings and a vector of an
        // entry per host page in it.
        let ok = unsafe {
            libc::mincore(
                host_from as *mut libc::c_void,
                (host_to - host_from) as usize,
                resident.as_mut_ptr().cast(),
            )
        } == 0;
        let mut at = from & !(page - 1);
        while at < to {
            let i = ((uaccess::g2h(at) - host_from) / host_page_size) as usize;
            let present = ok && resident[i] & 1 != 0;
            let mut e = if file { PM_FILE } else { 0 };
            if present {
                e |= PM_PRESENT;
                if !p.value.shared {
                    e |= PM_EXCLUSIVE;
                }
            }
            entries[(at / page - first) as usize] = e;
            at += page;
        }
    }
    let bytes: Vec<u8> = entries.iter().flat_map(|e| e.to_ne_bytes()).collect();
    uaccess::write_from(buf, &bytes)?;
    Ok(bytes.len() as u64)
}

/// Read `dst.len()` bytes of this process's memory at `addr`, as a tracer
/// reads it: all of it, or `Err` where some is not mapped or readable.
pub fn read_forced(addr: u64, dst: &mut [u8]) -> Result<(), i32> {
    let mut done = 0;
    while done < dst.len() {
        let at = addr.checked_add(done as u64).ok_or(errno::EIO)?;
        let n = in_page(at, (dst.len() - done) as u64) as usize;
        if !mapped(at) || uaccess::read_into(at, &mut dst[done..done + n]).is_err() {
            return Err(errno::EIO);
        }
        done += n;
    }
    Ok(())
}

/// Write `src` to this process's memory at `addr`, as a tracer writes it
/// (read-only private memory too): all of it, or `EIO`.
pub fn write_forced(addr: u64, src: &[u8]) -> Result<(), i32> {
    let mut done = 0;
    while done < src.len() {
        let at = addr.checked_add(done as u64).ok_or(errno::EIO)?;
        let n = in_page(at, (src.len() - done) as u64) as usize;
        if !force_write(at, &src[done..done + n]) {
            return Err(errno::EIO);
        }
        done += n;
    }
    Ok(())
}
