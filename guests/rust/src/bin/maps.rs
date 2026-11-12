//! The process's mappings as `/proc/self/maps`, `/proc/self/smaps`,
//! `PROCMAP_QUERY`, `mincore` and `/proc/self/status` report them: the
//! program and its stack, a file mapped from an offset, a shared mapping
//! with a page made read-only in the middle, locked memory, and a mapping
//! gone once unmapped. It prints what it observed, in terms that do not
//! depend on where things were placed.
//!
//! The C library calls go straight to the statically linked musl, declared
//! here, so the guest needs no crates.
use std::ffi::{CString, c_char};

const PROT_READ: i32 = 1;
const PROT_WRITE: i32 = 2;
const MAP_SHARED: i32 = 1;
const MAP_PRIVATE: i32 = 2;
const MAP_ANONYMOUS: i32 = 0x20;
/// `_IOWR('f', 17, struct procmap_query)`, passed as the `int` the C
/// library takes (its top bit set).
const PROCMAP_QUERY: i32 = 0xc068_6611_u32 as i32;
const PROCMAP_QUERY_VMA_EXECUTABLE: u64 = 4;

#[repr(C)]
#[derive(Default)]
struct ProcmapQuery {
    size: u64,
    query_flags: u64,
    query_addr: u64,
    vma_start: u64,
    vma_end: u64,
    vma_flags: u64,
    vma_page_size: u64,
    vma_offset: u64,
    inode: u64,
    dev_major: u32,
    dev_minor: u32,
    vma_name_size: u32,
    build_id_size: u32,
    vma_name_addr: u64,
    build_id_addr: u64,
}

unsafe extern "C" {
    fn memfd_create(name: *const c_char, flags: u32) -> i32;
    fn write(fd: i32, buf: *const u8, len: usize) -> isize;
    fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut u8;
    fn munmap(addr: *mut u8, len: usize) -> i32;
    fn mprotect(addr: *mut u8, len: usize, prot: i32) -> i32;
    fn mlock(addr: *const u8, len: usize) -> i32;
    fn mincore(addr: *mut u8, len: usize, vec: *mut u8) -> i32;
    fn open(path: *const c_char, flags: i32, ...) -> i32;
    fn ioctl(fd: i32, req: i32, ...) -> i32;
    fn getpagesize() -> i32;
    fn pipe(fds: *mut i32) -> i32;
    fn fork() -> i32;
    fn read(fd: i32, buf: *mut u8, len: usize) -> isize;
    fn waitpid(pid: i32, status: *mut i32, flags: i32) -> i32;
    fn _exit(code: i32) -> !;
    fn pwrite(fd: i32, buf: *const u8, len: usize, off: i64) -> isize;
    fn pread(fd: i32, buf: *mut u8, len: usize, off: i64) -> isize;
    fn ftruncate(fd: i32, len: i64) -> i32;
}

/// The lines of `/proc/self/maps` as (start, end, perms, offset, name).
fn maps() -> Vec<(u64, u64, String, u64, String)> {
    maps_of("self")
}

/// The lines of `/proc/<who>/maps`.
fn maps_of(who: &str) -> Vec<(u64, u64, String, u64, String)> {
    let text = std::fs::read_to_string(format!("/proc/{who}/maps")).unwrap();
    text.lines()
        .map(|l| {
            let mut f = l.split_whitespace();
            let range = f.next().unwrap();
            let (s, e) = range.split_once('-').unwrap();
            let perms = f.next().unwrap().to_string();
            let offset = u64::from_str_radix(f.next().unwrap(), 16).unwrap();
            let _dev = f.next();
            let _ino = f.next();
            let name = f.collect::<Vec<_>>().join(" ");
            (u64::from_str_radix(s, 16).unwrap(), u64::from_str_radix(e, 16).unwrap(), perms, offset, name)
        })
        .collect()
}

/// The perms of the lines covering `[start, end)`, in order.
fn perms_over(start: u64, end: u64) -> Vec<String> {
    maps().into_iter().filter(|m| m.0 < end && m.1 > start).map(|m| m.2).collect()
}

/// A field of `/proc/self/smaps` for the mapping starting at `start`, in kB.
fn smaps_field(start: u64, field: &str) -> u64 {
    smaps_field_of("self", start, field)
}

/// A field of `/proc/<who>/smaps` for the mapping starting at `start`.
fn smaps_field_of(who: &str, start: u64, field: &str) -> u64 {
    let text = std::fs::read_to_string(format!("/proc/{who}/smaps")).unwrap();
    let mut inside = false;
    for l in text.lines() {
        let first = l.split_whitespace().next().unwrap_or("");
        if let Some((s, e)) = first.split_once('-')
            && u64::from_str_radix(e, 16).is_ok()
            && let Ok(s) = u64::from_str_radix(s, 16)
        {
            inside = s == start;
        } else if inside && first == format!("{field}:") {
            return l.split_whitespace().nth(1).unwrap().parse().unwrap();
        }
    }
    u64::MAX
}

/// A large reservation mapped over, as Wine reserves the address space a
/// Windows program expects and maps into it: only what is touched takes
/// memory, and what is read back is zero.
fn reserve_and_map_over() {
    const PROT_NONE: i32 = 0;
    const PROT_RW: i32 = 3;
    const PRIVATE_ANON: i32 = 0x22;
    const FIXED: i32 = 0x10;
    const NORESERVE: i32 = 0x4000;
    let len = 4usize << 30;
    // SAFETY: fresh mappings of this program's, written within their length.
    let (zero, rss) = unsafe {
        let a = mmap(std::ptr::null_mut(), len, PROT_NONE, PRIVATE_ANON | NORESERVE, -1, 0);
        let b = mmap(a, len, PROT_RW, PRIVATE_ANON | FIXED, -1, 0);
        assert_eq!(a, b);
        *b.add(len / 2) = 1;
        let again = mmap(a, len, PROT_RW, PRIVATE_ANON | FIXED, -1, 0);
        (*again.add(len / 2) == 0 && *again.add(len - 1) == 0, rss_kb())
    };
    println!("reserved 4 GiB, mapped over twice: zero {zero}, under 256 MiB resident {}", rss < 256 << 10);
}

/// A private view of a file with no name (a memfd), as Wine maps the shared
/// memory its server writes: it shows what is written to the file until it
/// is itself written, then holds its own copy.
fn private_view() {
    let name = CString::new("view").unwrap();
    // SAFETY: a memfd of this program's, and mappings of it read and written
    // within their length.
    unsafe {
        let fd = memfd_create(name.as_ptr(), 0);
        ftruncate(fd, 65536);
        pwrite(fd, b"A".as_ptr(), 1, 4096);
        let v = mmap(std::ptr::null_mut(), 65536, 1, 2, fd, 0);
        pwrite(fd, b"B".as_ptr(), 1, 4096);
        let follows = *v.add(4096) as char;
        mprotect(v, 65536, 3);
        *v.add(4096) = b'C';
        let mut f = [0u8];
        pread(fd, f.as_mut_ptr(), 1, 4096);
        pwrite(fd, b"D".as_ptr(), 1, 4096);
        println!(
            "view: follows the file {follows}, its own write {}, the file kept {}, later file write {}",
            *v.add(4096) as char,
            f[0] as char,
            if *v.add(4096) == b'C' { "unseen" } else { "seen" }
        );
    }
}

/// This process's resident memory (`/proc/self/status`'s `VmRSS`), in KiB.
fn rss_kb() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let line = status.lines().find(|l| l.starts_with("VmRSS:")).unwrap();
    line.split_whitespace().nth(1).unwrap().parse().unwrap()
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("reserve") => return reserve_and_map_over(),
        Some("view") => return private_view(),
        _ => {}
    }
    // SAFETY: plain C library calls with valid arguments, on memory this
    // program maps for them.
    unsafe {
        let page = getpagesize() as usize;
        let exe = std::fs::read_link("/proc/self/exe").unwrap();
        let exe = exe.to_str().unwrap().to_string();
        let all = maps();
        let code = all.iter().find(|m| m.4 == exe && m.2.contains('x'));
        println!("program: listed with its code executable: {}", code.is_some());
        let stack = all.iter().find(|m| m.4 == "[stack]").map(|m| m.2.clone());
        println!("stack: {}", stack.unwrap_or_default());

        // A file mapped from its second page.
        let name = CString::new("maps-test").unwrap();
        let fd = memfd_create(name.as_ptr(), 0);
        write(fd, vec![7u8; 3 * page].as_ptr(), 3 * page);
        let f = mmap(std::ptr::null_mut(), 2 * page, PROT_READ, MAP_PRIVATE, fd, page as i64);
        let line = maps().into_iter().find(|m| m.0 == f as u64).unwrap();
        println!(
            "file: {} {}, from page {}, {} pages",
            line.2,
            line.4,
            line.3 / page as u64,
            (line.1 - line.0) / page as u64
        );

        // Shared memory with its middle page made read-only.
        let rw = PROT_READ | PROT_WRITE;
        let s = mmap(std::ptr::null_mut(), 3 * page, rw, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        mprotect(s.add(page), page, PROT_READ);
        let (lo, hi) = (s as u64, s as u64 + 3 * page as u64);
        println!("shared: {}", perms_over(lo, hi).join(" "));

        // Locked memory is in memory, and counted.
        let l = mmap(std::ptr::null_mut(), 4 * page, rw, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        let locked = mlock(l, 2 * page);
        let mut vec = vec![9u8; 2];
        let r = mincore(l, 2 * page, vec.as_mut_ptr());
        let resident = r == 0 && vec.iter().all(|&b| b & 1 != 0);
        let kb = (2 * page / 1024) as u64;
        println!(
            "mlock: {}, locked pages resident: {resident}, smaps Locked {}, Rss {}",
            locked,
            smaps_field(l as u64, "Locked") == kb,
            smaps_field(l as u64, "Rss") == kb
        );
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let vmlck: u64 = status
            .lines()
            .find_map(|l| l.strip_prefix("VmLck:"))
            .map_or(0, |v| v.trim().trim_end_matches(" kB").parse().unwrap());
        println!("status: VmLck covers it: {}", vmlck >= kb);

        // The program's code asked about by address.
        let maps_fd = open(c"/proc/self/maps".as_ptr(), 0);
        let mut buf = [0u8; 256];
        let mut q = ProcmapQuery {
            size: size_of::<ProcmapQuery>() as u64,
            query_addr: code.map_or(0, |m| m.0),
            vma_name_addr: buf.as_mut_ptr() as u64,
            vma_name_size: buf.len() as u32,
            ..ProcmapQuery::default()
        };
        let mut id = [0u8; 20];
        q.build_id_addr = id.as_mut_ptr() as u64;
        q.build_id_size = id.len() as u32;
        let r = ioctl(maps_fd, PROCMAP_QUERY, &mut q as *mut ProcmapQuery);
        let named = std::ffi::CStr::from_bytes_until_nul(&buf).unwrap().to_str().unwrap() == exe;
        println!(
            "query: {r}, the program's code: {}, executable: {}",
            named && q.vma_start == code.map_or(1, |m| m.0),
            q.vma_flags & PROCMAP_QUERY_VMA_EXECUTABLE != 0
        );
        // The build ID, as the program's file has it in its note.
        let file = std::fs::read("/proc/self/exe").unwrap();
        let head = [4u8, 0, 0, 0];
        let note = file.windows(16).position(|w| {
            w[..4] == head && w[8..12] == [3, 0, 0, 0] && &w[12..] == b"GNU\0"
        });
        let own = note.map(|at| {
            let n = u32::from_le_bytes(file[at + 4..at + 8].try_into().unwrap()) as usize;
            file[at + 16..at + 16 + n].to_vec()
        });
        let got = id[..q.build_id_size as usize].to_vec();
        println!("query: build ID of {} bytes, the file's: {}", got.len(), own == Some(got.clone()));
        // A buffer too small for it.
        q.build_id_size = 4;
        let short = ioctl(maps_fd, PROCMAP_QUERY, &mut q as *mut ProcmapQuery);
        println!("query: a short build ID buffer: {short} {}", std::io::Error::last_os_error().raw_os_error() == Some(36));

        // Unmapped: gone from the list.
        munmap(s, 3 * page);
        println!("unmapped: listed {}", perms_over(lo, hi).len());

        // A fork child that has changed nothing lists what it inherited.
        let mut hold = [0i32; 2];
        pipe(hold.as_mut_ptr());
        let idle = fork();
        if idle == 0 {
            let mut b = 0u8;
            read(hold[0], &mut b, 1);
            _exit(0);
        }
        let inherited = maps_of(&idle.to_string()).into_iter().any(|m| m.0 == f as u64 && m.2 == "r--p");
        println!("other: an idle fork child lists what it inherited: {inherited}");
        write(hold[1], b"x".as_ptr(), 1);
        let mut status = 0;
        waitpid(idle, &mut status, 0);

        // Another process's mappings: a child maps a file from its second
        // page and memory it fills, and waits while this one looks.
        let (mut up, mut down) = ([0i32; 2], [0i32; 2]);
        pipe(up.as_mut_ptr());
        pipe(down.as_mut_ptr());
        let child = fork();
        if child == 0 {
            let name = CString::new("maps-other").unwrap();
            let fd = memfd_create(name.as_ptr(), 0);
            write(fd, vec![7u8; 3 * page].as_ptr(), 3 * page);
            let f = mmap(std::ptr::null_mut(), 2 * page, PROT_READ, MAP_PRIVATE, fd, page as i64);
            let m = mmap(std::ptr::null_mut(), 4 * page, rw, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            std::ptr::write_bytes(m, 1, 4 * page);
            let addrs = [f as u64, m as u64];
            write(up[1], addrs.as_ptr().cast(), 16);
            let mut b = 0u8;
            read(down[0], &mut b, 1);
            _exit(0);
        }
        let mut addrs = [0u64; 2];
        read(up[0], addrs.as_mut_ptr().cast(), 16);
        let who = child.to_string();
        let line = maps_of(&who).into_iter().find(|m| m.0 == addrs[0]);
        println!(
            "other: {}",
            line.map_or("not listed".into(), |l| format!("{} {}, from page {}", l.2, l.4, l.3 / page as u64))
        );
        println!("other: its filled memory resident: {}", smaps_field_of(&who, addrs[1], "Rss") > 0);
        let fd = open(CString::new(format!("/proc/{who}/maps")).unwrap().as_ptr(), 0);
        let mut buf = [0u8; 256];
        let mut q = ProcmapQuery {
            size: size_of::<ProcmapQuery>() as u64,
            query_addr: addrs[0],
            vma_name_addr: buf.as_mut_ptr() as u64,
            vma_name_size: buf.len() as u32,
            ..ProcmapQuery::default()
        };
        let r = ioctl(fd, PROCMAP_QUERY, &mut q as *mut ProcmapQuery);
        let name = std::ffi::CStr::from_bytes_until_nul(&buf).unwrap().to_str().unwrap().to_string();
        println!("other: query {r}: {name}, offset {} pages", q.vma_offset / page as u64);
        write(down[1], b"x".as_ptr(), 1);
        let mut status = 0;
        waitpid(child, &mut status, 0);
        let gone = std::fs::read_to_string(format!("/proc/{who}/maps")).is_err();
        println!("other: gone with it: {gone}");
    }
}
