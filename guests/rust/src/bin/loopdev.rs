//! A loop device, as a program sets one up and uses it: a free device
//! from `/dev/loop-control`, a file attached, its contents read and
//! written through the device, from an offset and within a size limit,
//! mapped, at a position a fork child shares, shown in `/sys/block`, then
//! detached (and run down until closed); and a device added and removed. It prints what it observed,
//! in terms that do not depend on which device it was given.
//!
//! The C library calls go straight to the statically linked musl, declared
//! here, so the guest needs no crates.
use std::ffi::{CString, c_char};

const O_RDONLY: i32 = 0;
const O_RDWR: i32 = 2;
const O_CREAT: i32 = 0o100;
const O_TRUNC: i32 = 0o1000;
const SEEK_SET: i32 = 0;
const SEEK_CUR: i32 = 1;
const SEEK_END: i32 = 2;
const PROT_READ: i32 = 1;
const MAP_SHARED: i32 = 1;
const S_IFMT: u32 = 0o170000;
const S_IFBLK: u32 = 0o060000;

const LOOP_SET_FD: i32 = 0x4c00;
const LOOP_CLR_FD: i32 = 0x4c01;
const LOOP_SET_STATUS64: i32 = 0x4c04;
const LOOP_GET_STATUS64: i32 = 0x4c05;
const LOOP_CTL_ADD: i32 = 0x4c80;
const LOOP_CTL_REMOVE: i32 = 0x4c81;
const LOOP_CTL_GET_FREE: i32 = 0x4c82;
/// `_IOR(0x12, 114, size_t)`, passed as the `int` the C library takes.
const BLKGETSIZE64: i32 = 0x8008_1272_u32 as i32;
const BLKSSZGET: i32 = 0x1268;

const ENXIO: i32 = 6;
const EBUSY: i32 = 16;
const EINVAL: i32 = 22;
const ENOSPC: i32 = 28;

/// The backing file's size: not a whole number of sectors.
const FILE_SIZE: usize = 64 * 1024 + 100;
/// Where the device starts in the file once it is given an offset: on a
/// page of any size the host has, so the device can be mapped.
const OFFSET: usize = 16 * 1024;
/// The size limit then given.
const LIMIT: usize = 32 * 1024;

#[repr(C)]
struct LoopInfo64 {
    lo_device: u64,
    lo_inode: u64,
    lo_rdevice: u64,
    lo_offset: u64,
    lo_sizelimit: u64,
    lo_number: u32,
    lo_encrypt_type: u32,
    lo_encrypt_key_size: u32,
    lo_flags: u32,
    lo_file_name: [u8; 64],
    lo_crypt_name: [u8; 64],
    lo_encrypt_key: [u8; 32],
    lo_init: [u64; 2],
}

/// Linux arm64's `struct stat`, as far as it is read.
#[repr(C)]
struct Stat {
    st_dev: u64,
    st_ino: u64,
    st_mode: u32,
    st_nlink: u32,
    st_uid: u32,
    st_gid: u32,
    st_rdev: u64,
    rest: [u64; 12],
}

unsafe extern "C" {
    fn open(path: *const c_char, flags: i32, ...) -> i32;
    fn close(fd: i32) -> i32;
    fn read(fd: i32, buf: *mut u8, len: usize) -> isize;
    fn write(fd: i32, buf: *const u8, len: usize) -> isize;
    fn pread(fd: i32, buf: *mut u8, len: usize, off: i64) -> isize;
    fn pwrite(fd: i32, buf: *const u8, len: usize, off: i64) -> isize;
    fn lseek(fd: i32, off: i64, whence: i32) -> i64;
    fn ioctl(fd: i32, req: i32, ...) -> i32;
    fn stat(path: *const c_char, st: *mut Stat) -> i32;
    fn unlink(path: *const c_char) -> i32;
    fn getpid() -> i32;
    fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut u8;
    fn fork() -> i32;
    fn waitpid(pid: i32, status: *mut i32, flags: i32) -> i32;
    fn _exit(code: i32) -> !;
    fn __errno_location() -> *mut i32;
}

fn errno() -> i32 {
    // SAFETY: musl's thread-local errno.
    unsafe { *__errno_location() }
}

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

/// The byte at `i` of the backing file.
fn pattern(i: usize) -> u8 {
    (i % 251) as u8
}

/// `-errno` of a failed call, else its result.
fn res(r: i64) -> i64 {
    if r < 0 { -(errno() as i64) } else { r }
}

fn size64(fd: i32) -> i64 {
    let mut size = 0u64;
    // SAFETY: a valid out-parameter for the request.
    let r = unsafe { ioctl(fd, BLKGETSIZE64, &mut size) };
    if r < 0 { -(errno() as i64) } else { size as i64 }
}

fn read_file(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| format!("({e})"))
}

fn status(fd: i32) -> Result<LoopInfo64, i32> {
    // SAFETY: zeroed bytes are a valid `loop_info64`.
    let mut info: LoopInfo64 = unsafe { std::mem::zeroed() };
    // SAFETY: a valid out-parameter for the request.
    if unsafe { ioctl(fd, LOOP_GET_STATUS64, &mut info) } < 0 { Err(errno()) } else { Ok(info) }
}

fn main() {
    // SAFETY: plain calls into the C library throughout; every buffer is
    // a live local of the length passed.
    unsafe {
        let path = format!("/tmp/fwe-loopdev-{}.img", getpid());
        let cpath = c(&path);
        let file = open(cpath.as_ptr(), O_RDWR | O_CREAT | O_TRUNC, 0o600);
        let data: Vec<u8> = (0..FILE_SIZE).map(pattern).collect();
        assert_eq!(write(file, data.as_ptr(), data.len()), FILE_SIZE as isize);

        // A free device, from the control device.
        let ctl = open(c("/dev/loop-control").as_ptr(), O_RDWR);
        let n = ioctl(ctl, LOOP_CTL_GET_FREE);
        println!("free: {}", n >= 0);
        let dev_path = format!("/dev/loop{n}");
        let mut st: Stat = std::mem::zeroed();
        let r = stat(c(&dev_path).as_ptr(), &mut st);
        let (major, minor) = ((st.st_rdev >> 8) & 0xfff, (st.st_rdev & 0xff) | ((st.st_rdev >> 12) & !0xff));
        println!(
            "node: {r}, block device: {}, 7:N: {}",
            st.st_mode & S_IFMT == S_IFBLK,
            major == 7 && minor == n as u64
        );

        // Not attached yet: no status, no size, nothing to read.
        let dev = open(c(&dev_path).as_ptr(), O_RDWR);
        let mut buf = [0u8; 256];
        println!(
            "unattached: status {}, size {}, read {}",
            status(dev).err() == Some(ENXIO),
            size64(dev),
            read(dev, buf.as_mut_ptr(), buf.len())
        );

        // Attached: the file's whole sectors.
        println!("attach: {}", ioctl(dev, LOOP_SET_FD, file));
        println!("busy: {}", res(ioctl(dev, LOOP_SET_FD, file) as i64) == -(EBUSY as i64));
        let mut ssz = 0i32;
        ioctl(dev, BLKSSZGET, &mut ssz);
        println!("size: {}, sector size {ssz}", size64(dev));
        let sys = format!("/sys/block/loop{n}");
        println!("sys size: {}", read_file(&format!("{sys}/size")).trim());
        // The file's own path, its links resolved (`/tmp` may be one).
        let real = std::fs::canonicalize(&path).unwrap();
        println!(
            "sys backing file: {}",
            read_file(&format!("{sys}/loop/backing_file")).trim() == real.to_str().unwrap()
        );
        let got = read(dev, buf.as_mut_ptr(), 100);
        println!("read: {got}, the file's: {}", buf[..100] == data[..100]);
        let end = FILE_SIZE / 512 * 512;
        let got = pread(dev, buf.as_mut_ptr(), 200, end as i64 - 84);
        println!("read at the end: {got}, the file's: {}", buf[..84] == data[end - 84..end]);

        // From an offset, within a size limit.
        let mut info: LoopInfo64 = std::mem::zeroed();
        info.lo_offset = OFFSET as u64;
        info.lo_sizelimit = LIMIT as u64;
        info.lo_file_name[..4].copy_from_slice(b"test");
        println!("set status: {}", ioctl(dev, LOOP_SET_STATUS64, &info));
        println!("size: {}", size64(dev));
        let got = pread(dev, buf.as_mut_ptr(), 16, 0);
        println!("read at 0: {got}, the file's at the offset: {}", buf[..16] == data[OFFSET..OFFSET + 16]);
        println!("write: {}", pwrite(dev, b"xyz".as_ptr(), 3, 10));
        let mut back = [0u8; 3];
        pread(file, back.as_mut_ptr(), 3, OFFSET as i64 + 10);
        println!("written to the file after the offset: {}", &back == b"xyz");
        let past = pwrite(dev, b"x".as_ptr(), 1, LIMIT as i64);
        println!("write past the end: {}", res(past as i64) == -(ENOSPC as i64));
        println!(
            "seek: end {}, past it {}",
            lseek(dev, 0, SEEK_END),
            res(lseek(dev, LIMIT as i64 + 1, SEEK_SET)) == -(EINVAL as i64)
        );
        let s = status(dev).unwrap();
        let name_len = s.lo_file_name.iter().position(|&b| b == 0).unwrap_or(64);
        println!(
            "status: number {}, offset {}, limit {}, name {}",
            s.lo_number == n as u32,
            s.lo_offset,
            s.lo_sizelimit,
            String::from_utf8_lossy(&s.lo_file_name[..name_len])
        );

        // Mapped: the file's pages from the offset.
        let p = mmap(std::ptr::null_mut(), LIMIT, PROT_READ, MAP_SHARED, dev, 0);
        let mut expect = data[OFFSET..OFFSET + LIMIT].to_vec();
        expect[10..13].copy_from_slice(b"xyz");
        let mapped = p as isize != -1 && std::slice::from_raw_parts(p, LIMIT) == &expect[..];
        println!("mapped: {mapped}");

        // A fork child reads through the same open device, and moves the
        // position the parent sees.
        lseek(dev, 0, SEEK_SET);
        let pid = fork();
        if pid == 0 {
            let mut b = [0u8; 10];
            let ok = read(dev, b.as_mut_ptr(), 10) == 10 && b[..] == expect[..10];
            _exit(if ok { 0 } else { 1 });
        }
        let mut wstatus = 0;
        waitpid(pid, &mut wstatus, 0);
        println!("fork: child read {}, position shared {}", wstatus == 0, lseek(dev, 0, SEEK_CUR) == 10);

        // A device attached cannot be removed; detached, it has no status.
        println!("remove attached: {}", res(ioctl(ctl, LOOP_CTL_REMOVE, n) as i64) == -(EBUSY as i64));
        println!("detach: {}", ioctl(dev, LOOP_CLR_FD, 0));
        println!(
            "detached: again {}, status {}, size {}",
            res(ioctl(dev, LOOP_CLR_FD, 0) as i64) == -(ENXIO as i64),
            status(dev).err() == Some(ENXIO),
            size64(dev)
        );
        // Run down while this process holds it: another process neither
        // attaches it nor is given it as free; once closed, it does.
        let other = |expect_busy: bool| {
            let pid = fork();
            if pid == 0 {
                let d = open(c(&dev_path).as_ptr(), O_RDWR);
                let r = res(ioctl(d, LOOP_SET_FD, file) as i64);
                let ok = if expect_busy {
                    r == -(EBUSY as i64) && ioctl(ctl, LOOP_CTL_GET_FREE) != n
                } else {
                    r == 0 && ioctl(d, LOOP_CLR_FD, 0) == 0
                };
                _exit(if ok { 0 } else { 1 });
            }
            let mut wstatus = 0;
            waitpid(pid, &mut wstatus, 0);
            wstatus == 0
        };
        let held = other(true);
        close(dev);
        println!("run down: held {held}, closed {}", other(false));

        // A device added, then removed.
        let m = ioctl(ctl, LOOP_CTL_ADD, -1);
        let added = format!("/dev/loop{m}");
        let shown = stat(c(&added).as_ptr(), &mut st) == 0
            && read_file(&format!("/sys/block/loop{m}/dev")).trim() == format!("7:{m}");
        println!("added: {}, shown {shown}", m >= 0);
        println!("removed: {}, gone {}", ioctl(ctl, LOOP_CTL_REMOVE, m), stat(c(&added).as_ptr(), &mut st) != 0);
        let ro = open(c("/dev/loop-control").as_ptr(), O_RDONLY);
        println!("control read: {}", res(read(ro, buf.as_mut_ptr(), 1) as i64) == -(EINVAL as i64));

        close(ctl);
        close(file);
        unlink(cpath.as_ptr());
    }
}
