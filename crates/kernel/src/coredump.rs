//! Core dumps, as Linux writes them: a process that a signal whose default
//! action dumps core ends (`SIGQUIT`, `SIGSEGV`, `SIGABRT` and the like)
//! leaves an ELF core file of its memory and registers, named by
//! `kernel.core_pattern` (`core` in its directory by default, with
//! `.<pid>` if `kernel.core_uses_pid`), if it is dumpable
//! (`PR_SET_DUMPABLE`) and its `RLIMIT_CORE` allows at least a page; its
//! parent's `wait` then reports the core dumped (`WCOREDUMP`,
//! `CLD_DUMPED`).
//!
//! The host's own core dumps of fwe are off (its `RLIMIT_CORE` is 0, see
//! [`crate::rlimits::host_core_off`]): a host core would hold all of fwe's
//! reserved memory. So the parent learns of the dump from the wait status
//! the dying process leaves beside its record
//! ([`crate::procreg::ending`]).
//!
//! The file is what Linux's ELF core holds for a single thread: a
//! `PT_NOTE` of `NT_PRSTATUS` (the signal and the registers) and
//! `NT_PRPSINFO` (the process), then a `PT_LOAD` per mapping, with what
//! `coredump_filter`'s default (0x33) dumps: anonymous memory, private
//! file memory the process wrote (taken to be the writable kind), and the
//! first page of a file mapping that holds an ELF header, less memory
//! given `MADV_DONTDUMP`. Pages of zeros and those left out are holes,
//! which do not count against the limit. Past `RLIMIT_CORE` the file is
//! cut short, the core still reported dumped, as on Linux. That filter is
//! what `/proc/<pid>/coredump_filter` shows. A pipe (`|program`) in `core_pattern` is not run:
//! no core is dumped.

use crate::{Kernel, Platform, Regs};
use fwe_abi::{fcntl, signal};
use std::sync::atomic::{AtomicBool, Ordering};

/// `PR_SET_DUMPABLE` 0 was asked.
pub static UNDUMPABLE: AtomicBool = AtomicBool::new(false);

/// The guest's page: a mapping's contents are written in its units.
const PAGE: u64 = 4096;
/// `EM_AARCH64`.
const EM_AARCH64: u16 = 183;
const ET_CORE: u16 = 4;
const PT_LOAD: u32 = 1;
const PT_NOTE: u32 = 4;
const NT_PRSTATUS: u32 = 1;
const NT_PRPSINFO: u32 = 3;
/// `struct elf_prstatus` on arm64.
const PRSTATUS_SIZE: usize = 392;
/// `struct elf_prpsinfo` on a 64-bit machine.
const PRPSINFO_SIZE: usize = 136;

/// Whether `sig`'s default action dumps core.
pub fn dumps(sig: u64) -> bool {
    matches!(
        sig,
        signal::SIGQUIT
            | signal::SIGILL
            | signal::SIGTRAP
            | signal::SIGABRT
            | signal::SIGBUS
            | signal::SIGFPE
            | signal::SIGSEGV
            | signal::SIGXCPU
            | signal::SIGXFSZ
            | signal::SIGSYS
    )
}

/// This process dumped core.
static DUMPED: AtomicBool = AtomicBool::new(false);

/// The core-dumped bit of this ending process's wait status (`0x80`, or
/// 0).
pub fn status_bit() -> i32 {
    if DUMPED.load(Ordering::SeqCst) { 0x80 } else { 0 }
}

/// `core_pattern` with its `%` specifiers filled in.
fn core_name(pattern: &str, sig: u64, uid: u32, gid: u32, comm: &[u8], exe: &[u8]) -> Vec<u8> {
    // SAFETY: plain host calls.
    let host_pid = crate::host::pid();
    let pid = crate::thread::tgid();
    let mut out = Vec::new();
    let mut has_pid = false;
    let mut chars = pattern.bytes();
    while let Some(c) = chars.next() {
        if c != b'%' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some(b'%') => out.push(b'%'),
            Some(b'p') => {
                has_pid = true;
                out.extend_from_slice(pid.to_string().as_bytes());
            }
            Some(b'P') => {
                has_pid = true;
                out.extend_from_slice(host_pid.to_string().as_bytes());
            }
            Some(b'i') => out.extend_from_slice(crate::thread::tid().to_string().as_bytes()),
            Some(b'u') => out.extend_from_slice(uid.to_string().as_bytes()),
            Some(b'g') => out.extend_from_slice(gid.to_string().as_bytes()),
            Some(b's') => out.extend_from_slice(sig.to_string().as_bytes()),
            Some(b't') => {
                let t = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                out.extend_from_slice(t.to_string().as_bytes());
            }
            Some(b'h') => {
                let mut name = [0u8; 256];
                // SAFETY: a valid buffer of its length.
                if unsafe { libc::gethostname(name.as_mut_ptr().cast(), name.len()) } == 0 {
                    let n = name.iter().position(|&b| b == 0).unwrap_or(name.len());
                    out.extend_from_slice(&name[..n]);
                }
            }
            // The name, with any `/` made `!`, as Linux writes it.
            Some(b'e') => out.extend(comm.iter().map(|&b| if b == b'/' { b'!' } else { b })),
            Some(b'E') => out.extend(exe.iter().map(|&b| if b == b'/' { b'!' } else { b })),
            Some(b'c') => {
                let l = crate::rlimits::get(fwe_abi::resource::RLIMIT_CORE).0;
                out.extend_from_slice(l.to_string().as_bytes());
            }
            // Unknown, or a lone `%` at the end: dropped, as Linux does.
            _ => {}
        }
    }
    let uses_pid = crate::sysctl::number(b"kernel/core_uses_pid").unwrap_or(0) != 0;
    if uses_pid && !has_pid {
        out.extend_from_slice(format!(".{pid}").as_bytes());
    }
    out
}

/// One ELF note, padded.
fn note(out: &mut Vec<u8>, kind: u32, desc: &[u8]) {
    out.extend_from_slice(&5u32.to_le_bytes());
    out.extend_from_slice(&(desc.len() as u32).to_le_bytes());
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(b"CORE\0\0\0\0");
    out.extend_from_slice(desc);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

/// `/proc/<pid>/coredump_filter`: the filter the core follows, Linux's
/// default (anonymous and ELF header pages, private and shared).
pub const FILTER: &[u8] = b"00000033\n";

/// A mapping, and how much of it the core holds.
struct Segment {
    start: u64,
    end: u64,
    prot: u64,
    dump: u64,
}

/// What the core holds of each mapping, by `coredump_filter`'s default.
fn segments() -> Vec<Segment> {
    use crate::maps::Name;
    let Some(view) = crate::mm::MapsView::of(crate::host::pid()) else { return Vec::new() };
    view.areas
        .iter()
        .map(|p| {
            let a = &p.value;
            let len = p.end - p.start;
            let readable = a.prot & fwe_abi::mman::PROT_READ != 0;
            let file = matches!(a.object.name, Name::Exe | Name::Path(_));
            let dump = if !readable {
                0
            } else if !file || (!a.shared && a.prot & fwe_abi::mman::PROT_WRITE != 0) {
                len
            } else if !a.shared && a.object.offset == 0 && is_elf(p.start) {
                PAGE.min(len)
            } else {
                0
            };
            Segment { start: p.start, end: p.end, prot: a.prot, dump }
        })
        .collect()
}

fn is_elf(addr: u64) -> bool {
    let mut m = [0u8; 4];
    crate::uaccess::read_into(addr, &mut m).is_ok() && m == *b"\x7fELF"
}

/// Writes to the core, within the limit, holes for pages of zeros.
struct Out {
    fd: i32,
    pos: u64,
    written: u64,
    limit: u64,
    /// The limit was reached: the file ends there.
    full: bool,
}

impl Out {
    /// Write `data` at the current position: `false` once the limit is
    /// reached (as much as fits written, [`Out::full`] set) or on a failed
    /// write.
    fn put(&mut self, data: &[u8]) -> bool {
        let room = self.limit.saturating_sub(self.written) as usize;
        let (data, cut) = if data.len() > room { (&data[..room], true) } else { (data, false) };
        let mut done = 0;
        while done < data.len() {
            // SAFETY: a valid buffer; fwe's descriptor of the core.
            let n = unsafe {
                libc::pwrite(
                    self.fd,
                    data[done..].as_ptr().cast(),
                    data.len() - done,
                    (self.pos + done as u64) as libc::off_t,
                )
            };
            if n <= 0 {
                return false;
            }
            done += n as usize;
        }
        self.pos += data.len() as u64;
        self.written += data.len() as u64;
        self.full = cut;
        !cut
    }

    fn skip(&mut self, n: u64) {
        self.pos += n;
    }
}

impl<P: Platform> Kernel<P> {
    /// Dump core for `sig`, with the registers `regs` (or none), if Linux
    /// would: whether a core was dumped. Called as the process ends of it.
    pub fn dump_core(&mut self, sig: u64, regs: Option<&Regs>) -> bool {
        if !dumps(sig) || UNDUMPABLE.load(Ordering::Relaxed) {
            return false;
        }
        let limit = crate::rlimits::get(fwe_abi::resource::RLIMIT_CORE).0;
        if limit < PAGE {
            return false;
        }
        let pattern = crate::sysctl::text(b"kernel/core_pattern").unwrap_or_else(|| "core".into());
        if pattern.is_empty() || pattern.starts_with('|') {
            return false;
        }
        let record = crate::procreg::read(crate::host::pid());
        let comm = crate::thread::name()
            .map(|n| n[..n.iter().position(|&b| b == 0).unwrap_or(n.len())].to_vec())
            .or_else(|| record.as_ref().map(|r| r.comm.clone()))
            .unwrap_or_default();
        let exe = record.as_ref().map(|r| r.exe.clone()).unwrap_or_default();
        let (uid, gid) = (self.creds.uid, self.creds.gid);
        let name = core_name(&pattern, sig, uid, gid, &comm, &exe);
        if name.is_empty() {
            return false;
        }
        // As Linux: what is there is removed, and the core made anew, the
        // process's own, readable by it alone.
        let cwd = fcntl::AT_FDCWD as u64;
        let _ = self.unlink_path(cwd, name.clone(), 0);
        let flags = fcntl::O_CREAT | fcntl::O_EXCL | fcntl::O_WRONLY | fcntl::O_NOFOLLOW;
        let fd = self.open_path(cwd, name, flags, 0o600);
        if fd < 0 {
            return false;
        }
        let fd = fd as i32;
        let ok = self.write_core(fd, sig, regs, &comm, limit);
        // SAFETY: the descriptor opened above.
        // As a close of the guest's (the process ends right after).
        crate::inotify::closed(fd);
        crate::fdmarks::closed(fd);
        // SAFETY: the descriptor opened above.
        unsafe { libc::close(fd) };
        if ok {
            DUMPED.store(true, Ordering::SeqCst);
        }
        ok
    }

    fn write_core(&self, fd: i32, sig: u64, regs: Option<&Regs>, comm: &[u8], limit: u64) -> bool {
        let segs = segments();
        let phnum = segs.len() + 1;
        // SAFETY: plain host calls.
        let (ppid, pgrp, sid) = unsafe { (libc::getppid(), libc::getpgrp(), libc::getsid(0)) };
        let guest = |h: i32| crate::pidns::guest_ret(i64::from(h)) as i32;
        let pid = crate::thread::tgid();

        let mut status = [0u8; PRSTATUS_SIZE];
        status[0..4].copy_from_slice(&(sig as i32).to_le_bytes());
        status[12..14].copy_from_slice(&(sig as i16).to_le_bytes());
        status[16..24].copy_from_slice(&crate::thread::pending().to_le_bytes());
        status[24..32].copy_from_slice(&crate::thread::mask().to_le_bytes());
        status[32..36].copy_from_slice(&crate::thread::tid().to_le_bytes());
        status[36..40].copy_from_slice(&guest(ppid).to_le_bytes());
        status[40..44].copy_from_slice(&guest(pgrp).to_le_bytes());
        status[44..48].copy_from_slice(&guest(sid).to_le_bytes());
        if let Some(r) = regs {
            let words = r.x.iter().copied().chain([r.sp, r.pc, r.pstate]);
            for (i, w) in words.enumerate() {
                status[112 + i * 8..120 + i * 8].copy_from_slice(&w.to_le_bytes());
            }
        }

        let mut ps = [0u8; PRPSINFO_SIZE];
        ps[1] = b'R';
        ps[16..20].copy_from_slice(&self.creds.uid.to_le_bytes());
        ps[20..24].copy_from_slice(&self.creds.gid.to_le_bytes());
        ps[24..28].copy_from_slice(&pid.to_le_bytes());
        ps[28..32].copy_from_slice(&guest(ppid).to_le_bytes());
        ps[32..36].copy_from_slice(&guest(pgrp).to_le_bytes());
        ps[36..40].copy_from_slice(&guest(sid).to_le_bytes());
        let n = comm.len().min(15);
        ps[40..40 + n].copy_from_slice(&comm[..n]);
        let n = comm.len().min(79);
        ps[56..56 + n].copy_from_slice(&comm[..n]);

        let mut notes = Vec::new();
        note(&mut notes, NT_PRSTATUS, &status);
        note(&mut notes, NT_PRPSINFO, &ps);

        let headers = 64 + 56 * phnum as u64;
        let data_at = (headers + notes.len() as u64).next_multiple_of(PAGE);
        let mut head = Vec::with_capacity(headers as usize);
        head.extend_from_slice(b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0");
        head.extend_from_slice(&ET_CORE.to_le_bytes());
        head.extend_from_slice(&EM_AARCH64.to_le_bytes());
        head.extend_from_slice(&1u32.to_le_bytes());
        head.extend_from_slice(&0u64.to_le_bytes()); // e_entry
        head.extend_from_slice(&64u64.to_le_bytes()); // e_phoff
        head.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
        head.extend_from_slice(&0u32.to_le_bytes()); // e_flags
        head.extend_from_slice(&64u16.to_le_bytes()); // e_ehsize
        head.extend_from_slice(&56u16.to_le_bytes()); // e_phentsize
        head.extend_from_slice(&(phnum as u16).to_le_bytes());
        head.extend_from_slice(&64u16.to_le_bytes()); // e_shentsize
        head.extend_from_slice(&0u16.to_le_bytes()); // e_shnum
        head.extend_from_slice(&0u16.to_le_bytes()); // e_shstrndx
        let phdr =
            |h: &mut Vec<u8>, kind: u32, flags: u32, off: u64, va: u64, fsz: u64, msz: u64| {
                h.extend_from_slice(&kind.to_le_bytes());
                h.extend_from_slice(&flags.to_le_bytes());
                h.extend_from_slice(&off.to_le_bytes());
                h.extend_from_slice(&va.to_le_bytes());
                h.extend_from_slice(&0u64.to_le_bytes()); // p_paddr
                h.extend_from_slice(&fsz.to_le_bytes());
                h.extend_from_slice(&msz.to_le_bytes());
                h.extend_from_slice(&(if kind == PT_LOAD { PAGE } else { 4 }).to_le_bytes());
            };
        phdr(&mut head, PT_NOTE, 0, headers, 0, notes.len() as u64, 0);
        let mut at = data_at;
        for s in &segs {
            let mut flags = 0;
            if s.prot & fwe_abi::mman::PROT_READ != 0 {
                flags |= 4;
            }
            if s.prot & fwe_abi::mman::PROT_WRITE != 0 {
                flags |= 2;
            }
            if s.prot & fwe_abi::mman::PROT_EXEC != 0 {
                flags |= 1;
            }
            phdr(&mut head, PT_LOAD, flags, at, s.start, s.dump, s.end - s.start);
            at += s.dump;
        }

        let mut out = Out { fd, pos: 0, written: 0, limit, full: false };
        if !out.put(&head) || !out.put(&notes) {
            return out.full;
        }
        out.pos = data_at;
        let mut page = vec![0u8; PAGE as usize];
        for s in &segs {
            let mut a = s.start;
            while a < s.start + s.dump {
                // A page that cannot be read, holds only zeros or was
                // given `MADV_DONTDUMP` is a hole.
                let read =
                    !crate::mm::dont_dump(a) && crate::uaccess::read_into(a, &mut page).is_ok();
                if !read || page.iter().all(|&b| b == 0) {
                    out.skip(PAGE);
                } else if !out.put(&page) {
                    return out.full;
                }
                a += PAGE;
            }
        }
        // The file is as long as its last segment, holes and all.
        // SAFETY: fwe's descriptor of the core.
        unsafe { libc::ftruncate(fd, out.pos as libc::off_t) == 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `core_pattern`'s specifiers, as Linux fills them in.
    #[test]
    fn core_names() {
        let pid = crate::thread::tgid();
        let name =
            |p: &str| String::from_utf8(core_name(p, 11, 1000, 100, b"a/b", b"/bin/x")).unwrap();
        assert_eq!(name("core"), "core");
        assert_eq!(name("core.%p.%s.%u.%g"), format!("core.{pid}.11.1000.100"));
        assert_eq!(name("%e-%E-%%-%z"), "a!b-!bin!x-%-");
        assert!(dumps(fwe_abi::signal::SIGQUIT) && !dumps(fwe_abi::signal::SIGTERM));
    }
}
