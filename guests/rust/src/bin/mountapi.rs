//! The new mount API, in a mount namespace of the program's own: a tmpfs
//! made with `fsopen`, `fsconfig` and `fsmount` and attached with
//! `move_mount`; a detached copy of it (`open_tree`) attached beneath
//! another mount; a reconfiguration through `fspick`; `mount_setattr`;
//! and the mounts as `statx`, `statmount` and `listmount` report them. It
//! prints what it observed.
//!
//! The C library calls go straight to the statically linked musl, declared
//! here, so the guest needs no crates; the calls musl lacks are made with
//! `syscall`.
use std::ffi::{CString, c_char};

const AT_FDCWD: i64 = -100;
const CLONE_NEWNS: i32 = 0x20000;
const MS_REC: u64 = 0x4000;
const MS_PRIVATE: u64 = 1 << 18;
const MS_SHARED: u64 = 1 << 20;
const O_PATH: i32 = 0o10000000;

const SYS_OPEN_TREE: i64 = 428;
const SYS_MOVE_MOUNT: i64 = 429;
const SYS_FSOPEN: i64 = 430;
const SYS_FSCONFIG: i64 = 431;
const SYS_FSMOUNT: i64 = 432;
const SYS_FSPICK: i64 = 433;
const SYS_MOUNT_SETATTR: i64 = 442;
const SYS_STATMOUNT: i64 = 457;
const SYS_LISTMOUNT: i64 = 458;
const SYS_STATX: i64 = 291;

const FSCONFIG_SET_FLAG: u64 = 0;
const FSCONFIG_SET_STRING: u64 = 1;
const FSCONFIG_CMD_CREATE: u64 = 6;
const FSCONFIG_CMD_RECONFIGURE: u64 = 7;
const MOUNT_ATTR_NOEXEC: u64 = 0x8;
const MOUNT_ATTR_NODEV: u64 = 0x4;
const MOVE_MOUNT_F_EMPTY_PATH: u64 = 0x4;
const MOVE_MOUNT_T_EMPTY_PATH: u64 = 0x40;
const MOVE_MOUNT_BENEATH: u64 = 0x200;
const OPEN_TREE_CLONE: u64 = 1;
const STATX_MNT_ID_UNIQUE: u32 = 0x4000;
const STATMOUNT_MNT_BASIC: u64 = 0x2;
const STATMOUNT_MNT_POINT: u64 = 0x10;
const STATMOUNT_FS_TYPE: u64 = 0x20;
const LSMT_ROOT: u64 = u64::MAX;

unsafe extern "C" {
    fn unshare(flags: i32) -> i32;
    fn mount(src: *const c_char, target: *const c_char, fs: *const c_char, flags: u64, data: *const u8) -> i32;
    fn umount(target: *const c_char) -> i32;
    fn mkdir(path: *const c_char, mode: u32) -> i32;
    fn open(path: *const c_char, flags: i32, ...) -> i32;
    fn close(fd: i32) -> i32;
    fn read(fd: i32, buf: *mut u8, len: usize) -> isize;
    fn access(path: *const c_char, mode: i32) -> i32;
    fn getpid() -> i32;
    fn syscall(n: i64, ...) -> i64;
}

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

/// `statx` of `path`'s unique mount id.
fn mount_id(path: &str) -> u64 {
    let mut buf = [0u8; 256];
    let p = c(path);
    // SAFETY: a NUL-terminated path and a buffer of `struct statx`'s size.
    unsafe { syscall(SYS_STATX, AT_FDCWD, p.as_ptr(), 0, STATX_MNT_ID_UNIQUE, buf.as_mut_ptr()) };
    u64::from_ne_bytes(buf[144..152].try_into().unwrap())
}

/// The options `/proc/self/mountinfo` shows for the mount at `point`.
fn options_of(point: &str) -> String {
    let info = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    info.lines()
        .filter(|l| l.split(' ').nth(4) == Some(point))
        .last()
        .map(|l| l.split(' ').nth(5).unwrap_or("").to_string())
        .unwrap_or_default()
}

fn main() {
    // SAFETY: plain calls into the C library and the kernel throughout;
    // every buffer is a live local of the length passed.
    unsafe {
        unshare(CLONE_NEWNS);
        mount(std::ptr::null(), c("/").as_ptr(), std::ptr::null(), MS_REC | MS_PRIVATE, std::ptr::null());
        let base = format!("/tmp/fwe-mountapi-{}", getpid());
        let (a, b) = (format!("{base}/a"), format!("{base}/b"));
        for d in [&base, &a, &b] {
            mkdir(c(d).as_ptr(), 0o755);
        }
        // Mount points are shown with their links resolved (`/tmp` may be
        // one).
        let real = |p: &str| std::fs::canonicalize(p).unwrap().to_string_lossy().into_owned();
        let (a, b) = (real(&a), real(&b));

        // A tmpfs, configured, made, mounted detached, then attached.
        let fs = syscall(SYS_FSOPEN, c("tmpfs").as_ptr(), 0u32) as i32;
        let r1 = syscall(SYS_FSCONFIG, fs, FSCONFIG_SET_STRING, c("size").as_ptr(), c("1M").as_ptr(), 0);
        let bad = syscall(SYS_FSCONFIG, fs, FSCONFIG_SET_FLAG, c("bogus").as_ptr(), 0usize, 0);
        let mut msg = [0u8; 128];
        let n = read(fs, msg.as_mut_ptr(), msg.len());
        let r2 = syscall(SYS_FSCONFIG, fs, FSCONFIG_CMD_CREATE, 0usize, 0usize, 0);
        let mnt = syscall(SYS_FSMOUNT, fs, 0u32, MOUNT_ATTR_NOEXEC) as i32;
        let moved = syscall(SYS_MOVE_MOUNT, mnt, c("").as_ptr(), AT_FDCWD, c(&a).as_ptr(), MOVE_MOUNT_F_EMPTY_PATH);
        close(mnt);
        close(fs);
        println!(
            "fsopen: config {r1}, bogus {bad}, logged \"{}\", create {r2}, attached {moved}",
            String::from_utf8_lossy(&msg[..n.max(0) as usize])
        );
        std::fs::write(format!("{a}/A"), b"a").unwrap();
        println!("mounted: options {}", options_of(&a));

        // statx, statmount and listmount agree on it.
        let id = mount_id(&a);
        let mut req = [0u64; 3];
        req[0] = 24;
        req[1] = id;
        req[2] = STATMOUNT_MNT_BASIC | STATMOUNT_FS_TYPE | STATMOUNT_MNT_POINT;
        let mut sm = vec![0u8; 1024];
        let r = syscall(SYS_STATMOUNT, req.as_ptr(), sm.as_mut_ptr(), sm.len(), 0u32);
        let word = |at: usize| u32::from_ne_bytes(sm[at..at + 4].try_into().unwrap()) as usize;
        let string = |off: usize| {
            let s = &sm[512 + off..];
            String::from_utf8_lossy(&s[..s.iter().position(|&b| b == 0).unwrap()]).into_owned()
        };
        let same = u64::from_ne_bytes(sm[40..48].try_into().unwrap()) == id;
        println!("statmount: {r}, same id {same}, type {}, point {}", string(word(36)), string(word(108)) == a);
        let mut ids = [0u64; 64];
        let lreq = [24u64, LSMT_ROOT, 0];
        let n = syscall(SYS_LISTMOUNT, lreq.as_ptr(), ids.as_mut_ptr(), ids.len(), 0u32);
        println!("listmount: listed {}", n > 0 && ids[..n as usize].contains(&id));

        // A detached copy of it, attached beneath a tmpfs at b: b's on top,
        // the copy showing once b's is gone.
        mount(c("none").as_ptr(), c(&b).as_ptr(), c("tmpfs").as_ptr(), 0, std::ptr::null());
        std::fs::write(format!("{b}/B"), b"b").unwrap();
        let tree = syscall(SYS_OPEN_TREE, AT_FDCWD, c(&a).as_ptr(), OPEN_TREE_CLONE) as i32;
        let target = open(c(&b).as_ptr(), O_PATH);
        let flags = MOVE_MOUNT_BENEATH | MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH;
        let beneath = syscall(SYS_MOVE_MOUNT, tree, c("").as_ptr(), target, c("").as_ptr(), flags);
        close(tree);
        close(target);
        let sees = |f: &str| access(c(&format!("{b}/{f}")).as_ptr(), 0) == 0;
        let on_top = sees("B") && !sees("A");
        umount(c(&b).as_ptr());
        println!("beneath: {beneath}, top first {on_top}, then the copy {}", sees("A") && !sees("B"));
        umount(c(&b).as_ptr());

        // Reconfigured read-only through fspick, and back.
        let pick = syscall(SYS_FSPICK, AT_FDCWD, c(&a).as_ptr(), 0u32) as i32;
        syscall(SYS_FSCONFIG, pick, FSCONFIG_SET_FLAG, c("ro").as_ptr(), 0usize, 0);
        let r = syscall(SYS_FSCONFIG, pick, FSCONFIG_CMD_RECONFIGURE, 0usize, 0usize, 0);
        let ro = options_of(&a).starts_with("ro");
        syscall(SYS_FSCONFIG, pick, FSCONFIG_SET_FLAG, c("rw").as_ptr(), 0usize, 0);
        syscall(SYS_FSCONFIG, pick, FSCONFIG_CMD_RECONFIGURE, 0usize, 0usize, 0);
        close(pick);
        println!("fspick: {r}, read-only {ro}, then {}", &options_of(&a)[..2]);

        // mount_setattr: a flag and the propagation.
        let attr = [MOUNT_ATTR_NODEV, 0, MS_SHARED, 0];
        let r = syscall(SYS_MOUNT_SETATTR, AT_FDCWD, c(&a).as_ptr(), 0u32, attr.as_ptr(), 32usize);
        let info = std::fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
        let line = info.lines().find(|l| l.split(' ').nth(4) == Some(a.as_str())).unwrap_or("");
        println!(
            "mount_setattr: {r}, nodev {}, shared {}",
            options_of(&a).contains("nodev"),
            line.contains(" shared:")
        );
        umount(c(&a).as_ptr());
    }
}
