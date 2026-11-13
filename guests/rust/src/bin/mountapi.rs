//! The new mount API, in a mount namespace of the program's own: a tmpfs
//! made with `fsopen`, `fsconfig` and `fsmount` and attached with
//! `move_mount`; a detached copy of it (`open_tree`) attached beneath
//! another mount; a reconfiguration through `fspick`; `mount_setattr`;
//! the mounts as `statx`, `statmount` and `listmount` report them; a mount
//! under a shared one reaching a child's copy of the namespace; and the
//! mount flags and a busy mount enforced. It prints what it observed.
//!
//! `mountapi procfd` reads `/proc` through a descriptor of a procfs
//! instance, made with `fsmount` and cloned with `open_tree`.
//!
//! `mountapi selfclone` does what crun and runc do to run a copy of
//! themselves no container can write: unless `/proc/self/exe` is on a
//! read-only mount, it clones its own binary's mount (`open_tree`), makes
//! the clone read-only (`mount_setattr`) and runs itself again through
//! it (`execveat`), once; then it prints what `fstatfs` of its binary
//! says.
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
    fn fork() -> i32;
    fn pipe(fds: *mut i32) -> i32;
    fn write(fd: i32, buf: *const u8, len: usize) -> isize;
    fn waitpid(pid: i32, status: *mut i32, flags: i32) -> i32;
    fn _exit(code: i32) -> !;
    fn umount2(target: *const c_char, flags: i32) -> i32;
    fn mknod(path: *const c_char, mode: u32, dev: u64) -> i32;
    fn symlink(target: *const c_char, path: *const c_char) -> i32;
    fn execv(path: *const c_char, argv: *const *const c_char) -> i32;
    fn __errno_location() -> *mut i32;
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

/// Whether this program's binary is on a read-only mount, as runc's
/// `IsSelfExeCloned` asks.
fn self_read_only() -> bool {
    const ST_RDONLY: u64 = 1;
    let mut st = [0u64; 15];
    // SAFETY: a NUL-terminated path; a `struct statfs` sized buffer.
    unsafe {
        let fd = open(c"/proc/self/exe".as_ptr(), 0o2000000);
        let r = syscall(44, fd, st.as_mut_ptr());
        close(fd);
        // f_flags is the last but four words of Linux's `struct statfs`.
        r == 0 && st[10] & ST_RDONLY != 0
    }
}

fn self_clone(again: bool) {
    const OPEN_TREE_CLONE: u32 = 1;
    const AT_RECURSIVE: u32 = 0x8000;
    const O_CLOEXEC: u32 = 0o2000000;
    const AT_EMPTY_PATH: u32 = 0x1000;
    const MOUNT_ATTR_RDONLY: u64 = 0x1;
    if self_read_only() || again {
        println!("cloned: read-only {}, re-ran {again}", self_read_only());
        return;
    }
    // SAFETY: plain calls with NUL-terminated paths and live buffers.
    unsafe {
        let fd = syscall(
            SYS_OPEN_TREE,
            AT_FDCWD,
            c"/proc/self/exe".as_ptr(),
            OPEN_TREE_CLONE | AT_RECURSIVE | O_CLOEXEC,
        ) as i32;
        let attr = [MOUNT_ATTR_RDONLY, 0, 0, 0];
        let r = syscall(SYS_MOUNT_SETATTR, fd, c"".as_ptr(), AT_EMPTY_PATH, attr.as_ptr(), 32usize);
        let argv = [c"mountapi".as_ptr(), c"selfclone".as_ptr(), c"again".as_ptr(), std::ptr::null()];
        let env: [*const c_char; 1] = [std::ptr::null()];
        syscall(281, fd, c"".as_ptr(), argv.as_ptr(), env.as_ptr(), AT_EMPTY_PATH);
        println!("clone failed: open_tree {fd}, mount_setattr {r}");
    }
}

/// `/proc` reached through a descriptor of a procfs instance, as crun
/// reaches it: one made with `fsopen`/`fsmount`, and a clone of `/proc`
/// (`open_tree`); a file read relative to each.
fn proc_fd() {
    const OPEN_TREE_CLONE: u32 = 1;
    let read_at = |dfd: i32| {
        let mut buf = [0u8; 16];
        // SAFETY: a NUL-terminated path; a live buffer of its length.
        unsafe {
            let fd = syscall(56, dfd, c"sys/kernel/cap_last_cap".as_ptr(), 0i64, 0i64) as i32;
            if fd < 0 {
                return format!("open failed ({})", *__errno_location());
            }
            let n = read(fd, buf.as_mut_ptr(), buf.len());
            close(fd);
            String::from_utf8_lossy(&buf[..n.max(0) as usize]).trim().to_string()
        }
    };
    // SAFETY: plain calls with NUL-terminated strings.
    unsafe {
        let fs = syscall(SYS_FSOPEN, c"proc".as_ptr(), 0u32) as i32;
        syscall(SYS_FSCONFIG, fs, FSCONFIG_CMD_CREATE, 0usize, 0usize, 0);
        let mnt = syscall(SYS_FSMOUNT, fs, 0u32, 0u64) as i32;
        println!("fsmount proc: cap_last_cap {}", read_at(mnt));
        for f in [c"mounts", c"self/mountinfo", c"self/status", c"self/cgroup"] {
            let fd = syscall(56, mnt, f.as_ptr(), 0i64, 0i64) as i32;
            let mut buf = [0u8; 4096];
            let n = if fd >= 0 { read(fd, buf.as_mut_ptr(), buf.len()) } else { -1 };
            println!("{}: {}", f.to_str().unwrap(), if n > 0 { "read" } else { "missing" });
            close(fd);
        }
        let tree = syscall(SYS_OPEN_TREE, AT_FDCWD, c"/proc".as_ptr(), OPEN_TREE_CLONE) as i32;
        println!("open_tree /proc: cap_last_cap {}", read_at(tree));
        // Attached in a mount namespace of its own, then remounted with
        // flags through a descriptor of its mount point, as crun does.
        unshare(CLONE_NEWNS);
        mount(std::ptr::null(), c"/".as_ptr(), std::ptr::null(), MS_REC | MS_PRIVATE, std::ptr::null());
        let dir = format!("/tmp/fwe-procfd-{}", getpid());
        mkdir(c(&dir).as_ptr(), 0o755);
        let dir = std::fs::canonicalize(&dir).unwrap().to_string_lossy().into_owned();
        let moved = syscall(SYS_MOVE_MOUNT, mnt, c"".as_ptr(), AT_FDCWD, c(&dir).as_ptr(), MOVE_MOUNT_F_EMPTY_PATH);
        let target = open(c(&dir).as_ptr(), O_PATH | 0o2000000);
        let through = format!("/proc/self/fd/{target}");
        const MS_REMOUNT: u64 = 32;
        const MS_BIND: u64 = 4096;
        const MS_NOSUID: u64 = 2;
        const MS_NODEV: u64 = 4;
        const MS_NOEXEC: u64 = 8;
        let flags = MS_REMOUNT | MS_BIND | MS_NOSUID | MS_NODEV | MS_NOEXEC;
        let r = mount(std::ptr::null(), c(&through).as_ptr(), std::ptr::null(), flags, std::ptr::null());
        let e = if r < 0 { *__errno_location() } else { 0 };
        let r2 = mount(std::ptr::null(), c(&dir).as_ptr(), std::ptr::null(), flags, std::ptr::null());
        let e2 = if r2 < 0 { *__errno_location() } else { 0 };
        // Through the descriptor it was attached with: it names the mount.
        let attr = [MOUNT_ATTR_NODEV, 0, 0, 0];
        let r3 = syscall(SYS_MOUNT_SETATTR, mnt, c"".as_ptr(), 0x1000u32, attr.as_ptr(), 32usize);
        println!("proc attached {moved}; remount through fd {r} ({e}), by path {r2} ({e2}); setattr through its descriptor {r3}");
        umount2(c(&dir).as_ptr(), 2);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("procfd") {
        proc_fd();
        return;
    }
    if args.get(1).map(String::as_str) == Some("selfclone") {
        self_clone(args.get(2).map(String::as_str) == Some("again"));
        return;
    }
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

        // Propagation: a shared mount, a child in a copy of the namespace
        // (its peer), a mount made under it here reaching the child there,
        // and its unmount too.
        mount(c("none").as_ptr(), c(&b).as_ptr(), c("tmpfs").as_ptr(), 0, std::ptr::null());
        mount(std::ptr::null(), c(&b).as_ptr(), std::ptr::null(), MS_SHARED, std::ptr::null());
        mkdir(c(&format!("{b}/sub")).as_ptr(), 0o755);
        let (mut go, mut back) = ([0i32; 2], [0i32; 2]);
        pipe(go.as_mut_ptr());
        pipe(back.as_mut_ptr());
        let pid = fork();
        if pid == 0 {
            unshare(CLONE_NEWNS);
            write(back[1], b"r".as_ptr(), 1);
            let mut x = [0u8; 1];
            read(go[0], x.as_mut_ptr(), 1);
            let there = std::fs::read(format!("{b}/sub/P")).is_ok();
            write(back[1], [there as u8].as_ptr(), 1);
            read(go[0], x.as_mut_ptr(), 1);
            let gone = std::fs::read(format!("{b}/sub/P")).is_err();
            write(back[1], [gone as u8].as_ptr(), 1);
            _exit(0);
        }
        let mut x = [0u8; 1];
        read(back[0], x.as_mut_ptr(), 1);
        mount(c("none").as_ptr(), c(&format!("{b}/sub")).as_ptr(), c("tmpfs").as_ptr(), 0, std::ptr::null());
        std::fs::write(format!("{b}/sub/P"), b"p").unwrap();
        write(go[1], b"g".as_ptr(), 1);
        read(back[0], x.as_mut_ptr(), 1);
        let reached = x[0] == 1;
        umount(c(&format!("{b}/sub")).as_ptr());
        write(go[1], b"g".as_ptr(), 1);
        read(back[0], x.as_mut_ptr(), 1);
        let mut status = 0;
        waitpid(pid, &mut status, 0);
        println!("propagation: into the copied namespace {reached}, unmount too {}", x[0] == 1);
        umount(c(&b).as_ptr());

        // The mount flags acted on, and a busy mount refused.
        let errno = || *__errno_location();
        const MS_NODEV: u64 = 4;
        const MS_NOEXEC: u64 = 8;
        const MS_NOSYMFOLLOW: u64 = 256;
        let flags = MS_NODEV | MS_NOEXEC | MS_NOSYMFOLLOW;
        mount(c("none").as_ptr(), c(&b).as_ptr(), c("tmpfs").as_ptr(), flags, std::ptr::null());
        let node = format!("{b}/null");
        mknod(c(&node).as_ptr(), 0o20666, (1 << 8) | 3);
        let nodev = open(c(&node).as_ptr(), 2) == -1 && errno() == 13;
        let prog = format!("{b}/prog");
        std::fs::copy("/proc/self/exe", &prog).unwrap();
        let prog_c = c(&prog);
        let argv = [prog_c.as_ptr(), std::ptr::null()];
        let noexec = execv(argv[0], argv.as_ptr()) == -1 && errno() == 13;
        symlink(c(&node).as_ptr(), c(&format!("{b}/link")).as_ptr());
        let nofollow = open(c(&format!("{b}/link")).as_ptr(), 0) == -1 && errno() == 40;
        // A mapping of a file there may not be made executable later either.
        let pfd = open(prog_c.as_ptr(), 0);
        let map = syscall(222, 0i64, 4096i64, 1i64, 2i64, pfd as i64, 0i64);
        let no_mprotect = syscall(226, map, 4096i64, 5i64) == -1 && errno() == 13;
        syscall(215, map, 4096i64);
        close(pfd);
        println!("enforced: nodev {nodev}, noexec {noexec} (mprotect too {no_mprotect}), nosymfollow {nofollow}");
        let held = open(c(&format!("{b}/prog")).as_ptr(), 0);
        let busy = umount(c(&b).as_ptr()) == -1 && errno() == 16;
        close(held);
        const MNT_EXPIRE: i32 = 4;
        let first = umount2(c(&b).as_ptr(), MNT_EXPIRE) == -1 && errno() == 11;
        let second = umount2(c(&b).as_ptr(), MNT_EXPIRE) == 0;
        println!("unmount: busy refused {busy}, expire marks {first}, then unmounts {second}");

        // Access times: kept on a noatime mount though relatime would move
        // them, moved on a strictatime one though relatime would not, and a
        // remount that names none keeps the mount's.
        const MS_REMOUNT: u64 = 32;
        const MS_NOATIME: u64 = 1024;
        const MS_STRICTATIME: u64 = 1 << 24;
        mount(c("none").as_ptr(), c(&b).as_ptr(), c("tmpfs").as_ptr(), MS_NOATIME, std::ptr::null());
        let file = format!("{b}/f");
        std::fs::write(&file, b"x").unwrap();
        let atime_after_read = |set: i64| {
            use std::os::unix::fs::MetadataExt;
            let times = [set, 0i64, 0, (1 << 30) - 2];
            syscall(88, -100i64, c(&file).as_ptr(), times.as_ptr(), 0);
            std::fs::read(&file).unwrap();
            std::fs::metadata(&file).unwrap().atime()
        };
        let kept = atime_after_read(1000) == 1000;
        let recent = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64 - 60;
        let remount = |flags: u64| mount(c("none").as_ptr(), c(&b).as_ptr(), std::ptr::null(), MS_REMOUNT | flags, std::ptr::null());
        remount(MS_STRICTATIME);
        let moved = atime_after_read(recent) > recent;
        remount(0);
        let still = atime_after_read(recent) > recent;
        println!("atime: noatime keeps {kept}, strictatime moves {moved}, remount keeps the mode {still}");
        umount(c(&b).as_ptr());

        // A standard device node bound over a file (as runtimes mask
        // paths with /dev/null): the file is the device now.
        let masked = format!("{base}/masked");
        std::fs::write(&masked, b"secret").unwrap();
        const MS_BIND: u64 = 4096;
        let r = mount(c("/dev/null").as_ptr(), c(&masked).as_ptr(), std::ptr::null(), MS_BIND, std::ptr::null());
        let is_dev = {
            use std::os::unix::fs::FileTypeExt;
            std::fs::metadata(&masked).map(|m| m.file_type().is_char_device()).unwrap_or(false)
        };
        let empty = std::fs::read(&masked).map(|d| d.is_empty()).unwrap_or(false);
        println!("device bind: {r}, a device {is_dev}, reads empty {empty}");
        umount(c(&masked).as_ptr());
    }
}
