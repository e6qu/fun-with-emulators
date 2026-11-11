//! End-to-end tests: build Linux arm64 programs from `guests/` and run them
//! under `fwe`.
//!
//! Assembly guests are assembled with `clang` and linked with the toolchain's
//! `rust-lld` three ways: as static executables above 4 GiB, as static
//! position-independent executables, and (`-low`) at the default low link
//! address, which the native backend must reject cleanly. Rust guests are
//! built for `aarch64-unknown-linux-musl`.

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// How long a guest may run before the harness kills it. A guest should
/// finish in well under a second; a hang (e.g. a thread that never wakes)
/// becomes a fast, visible failure instead of hanging CI.
const GUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// The same for a guest on the hypervisor stand-in, which emulates every
/// instruction (and checks for a stop at every block, the only safe way to
/// stop a Unicorn engine): a guest doing about a second of work natively
/// (`x18spin`) takes about 5 s there alone and over 20 s on a loaded CI
/// runner. Still a fast failure for a hang.
const STANDIN_TIMEOUT: Duration = Duration::from_secs(120);

/// Run a command, killing it if it exceeds [`GUEST_TIMEOUT`]. The returned
/// `Output` has a non-success status on timeout, and its captured output is
/// preserved for the failure message.
///
/// stdout and stderr are drained on their own threads, so a guest that writes
/// a lot (e.g. many `--strace` lines) never blocks on a full pipe.
fn run_bounded(mut cmd: Command) -> Output {
    cmd.stdin(Stdio::null());
    run_bounded_with_stdin(cmd, &[])
}

/// [`run_bounded`] for a command that runs VM processes (the hypervisor
/// backend). A VM process must never be killed with its VM alive, so the
/// command runs in a process group of its own; on timeout the group gets
/// `SIGTERM`, which every VM process catches to tear its VM down first,
/// and only a leader still alive 5 s later gets `SIGKILL`. Afterwards no
/// process of the group may be left (a fork child outliving its test would
/// keep a VM running alongside the next one): the test fails if one is.
fn run_vm_bounded(cmd: Command) -> Output {
    run_vm_bounded_for(cmd, GUEST_TIMEOUT)
}

/// [`run_vm_bounded`] with a time limit of `limit`.
fn run_vm_bounded_for(mut cmd: Command, limit: Duration) -> Output {
    use std::os::unix::process::CommandExt;
    cmd.stdin(Stdio::null()).process_group(0);
    let out = run_bounded_inner(cmd, &[], limit, true);
    // The leader is reaped; anything still in its group outlived it.
    let pgid = out.1;
    let lingering = || {
        // SAFETY: signal 0 only checks whether the group has members.
        unsafe { libc::killpg(pgid, 0) == 0 }
    };
    if lingering() {
        // SAFETY: asking the leftover processes to end (and tear down).
        unsafe { libc::killpg(pgid, libc::SIGTERM) };
        let start = Instant::now();
        while lingering() && start.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("a process of a VM test outlived it (process group {pgid})");
    }
    out.0
}

/// Like [`run_bounded`], but feeds `input` to the guest's standard input
/// (written on its own thread so a guest that does not read it cannot wedge
/// the test).
fn run_bounded_with_stdin(cmd: Command, input: &[u8]) -> Output {
    run_bounded_for(cmd, input, GUEST_TIMEOUT)
}

/// Like [`run_bounded_with_stdin`], with a time limit of `limit` (for a real
/// program's workload that starts many processes).
fn run_bounded_for(cmd: Command, input: &[u8], limit: Duration) -> Output {
    run_bounded_inner(cmd, input, limit, false).0
}

/// The guest's output and its pid, killing it after `limit`. With `vm`, the
/// command leads its own process group, and a timeout ends the group gently
/// (see [`run_vm_bounded`]).
fn run_bounded_inner(mut cmd: Command, input: &[u8], limit: Duration, vm: bool) -> (Output, i32) {
    use std::io::{Read, Write};
    use std::os::unix::process::CommandExt;
    // Its own process group, so a timeout reaches the processes it starts.
    cmd.process_group(0);
    let feed = !input.is_empty();
    if feed {
        cmd.stdin(Stdio::piped());
    }
    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    if feed {
        let mut stdin = child.stdin.take().unwrap();
        let data = input.to_vec();
        std::thread::spawn(move || {
            let _ = stdin.write_all(&data);
            // Dropping `stdin` closes it, signalling EOF to the guest.
        });
    }
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let out_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        buf
    });
    let err_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr.read_to_end(&mut buf);
        buf
    });

    let start = Instant::now();
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if start.elapsed() > limit {
            timed_out = true;
            if vm {
                let pgid = child.id() as i32;
                // SAFETY: SIGTERM to the guest's own process group; VM
                // processes catch it and tear their VM down.
                unsafe { libc::killpg(pgid, libc::SIGTERM) };
                let grace = Instant::now();
                while grace.elapsed() < Duration::from_secs(5) {
                    if child.try_wait().unwrap().is_some() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                if child.try_wait().unwrap().is_none() {
                    eprintln!("--- VM guest ignored SIGTERM for 5 s; killing it");
                    let _ = child.kill();
                }
            } else {
                // SAFETY: SIGKILL to the guest's own process group.
                unsafe { libc::killpg(child.id() as i32, libc::SIGKILL) };
            }
            break child.wait().unwrap();
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    if timed_out {
        eprintln!("--- guest timed out after {limit:?} (killed)");
    }
    // Readers finish once the pipes close: at the exit of the last process
    // holding them, which may have left the group. One still holding them
    // a while later is reported, not waited for.
    let joined = |reader: std::thread::JoinHandle<Vec<u8>>, which: &str| {
        let start = Instant::now();
        while !reader.is_finished() {
            if start.elapsed() > Duration::from_secs(10) {
                eprintln!("--- a process outlived the guest holding its {which}");
                return Vec::new();
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        reader.join().unwrap()
    };
    let stdout = joined(out_reader, "standard output");
    let stderr = joined(err_reader, "standard error");
    (Output { status, stdout, stderr }, child.id() as i32)
}

const ASM_GUESTS: &[&str] = &[
    "pacbti",
    "mapfixed",
    "mapfixedmt",
    "hello",
    "exit42",
    "enosys",
    "regs",
    "tpidr",
    "x18",
    "x18spin",
    "x18mem",
    "x18dp",
    "x18ldst",
    "x18br",
    "x18fp",
    "x18pc",
    "x18sig",
    "fpsig",
    "efault",
    "sigmap",
    "hvsys",
    "pipethread",
    "fileio",
    "sigtest",
    "threadtest",
    "clone3test",
    "execer",
    "execee",
    "forktest",
    "procread",
    "epolltest",
    "eventfdtest",
    "timerfdtest",
    "socketpairtest",
    "jobctl",
    "credtest",
    "signalfdtest",
    "procdir",
];

/// Link address of the fixed-address (ET_EXEC) guests, above macOS's
/// reserved low 4 GiB.
const IMAGE_BASE: &str = "--image-base=0x10000000000";

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

fn out_dir() -> PathBuf {
    repo().join("target/guests")
}

fn run_checked(cmd: &mut Command) {
    let out = cmd.output().unwrap_or_else(|e| panic!("running {cmd:?}: {e}"));
    assert!(
        out.status.success(),
        "{cmd:?} failed:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn rust_lld() -> PathBuf {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let sysroot = Command::new(&rustc).args(["--print", "sysroot"]).output().unwrap();
    let sysroot = String::from_utf8(sysroot.stdout).unwrap();
    let host = Command::new(&rustc).args(["--print", "host-tuple"]).output().unwrap();
    let host = String::from_utf8(host.stdout).unwrap();
    Path::new(sysroot.trim()).join("lib/rustlib").join(host.trim()).join("bin/rust-lld")
}

fn build_guests() -> &'static Path {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let out = out_dir();
        let asm = out.join("asm");
        std::fs::create_dir_all(&asm).unwrap();
        let lld = rust_lld();
        for name in ASM_GUESTS {
            let src = repo().join("guests/asm").join(format!("{name}.S"));
            let obj = asm.join(format!("{name}.o"));
            run_checked(
                Command::new("clang")
                    .args(["--target=aarch64-linux-gnu", "-c", "-o"])
                    .arg(&obj)
                    .arg(&src),
            );
            run_checked(
                Command::new(&lld)
                    .args(["-flavor", "gnu", "-static", IMAGE_BASE, "-o"])
                    .arg(asm.join(name))
                    .arg(&obj),
            );
            run_checked(
                Command::new(&lld)
                    .args(["-flavor", "gnu", "-static", "-o"])
                    .arg(asm.join(format!("{name}-low")))
                    .arg(&obj),
            );
            run_checked(
                Command::new(&lld)
                    .args(["-flavor", "gnu", "-pie", "--no-dynamic-linker", "-o"])
                    .arg(asm.join(format!("{name}-pie")))
                    .arg(&obj),
            );
        }
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let mut build = Command::new(cargo);
        build
            .args(["build", "--release", "--manifest-path"])
            .arg(repo().join("guests/rust/Cargo.toml"))
            .arg("--target-dir")
            .arg(out.join("rust"))
            // Cargo reads guests/rust/.cargo/config.toml from the working
            // directory.
            .current_dir(repo().join("guests/rust"));
        // Do not inherit the outer build's flags or target settings.
        for (key, _) in std::env::vars() {
            if key.starts_with("CARGO_") || key == "RUSTFLAGS" || key == "RUSTC_WRAPPER" {
                build.env_remove(key);
            }
        }
        run_checked(&mut build);
        out
    })
}

fn asm_guest(name: &str) -> PathBuf {
    build_guests().join("asm").join(name)
}

fn rust_guest(name: &str) -> PathBuf {
    build_guests().join("rust/aarch64-unknown-linux-musl/release").join(name)
}

fn fwe(program: &Path, args: &[&str]) -> Output {
    fwe_within(program, args, GUEST_TIMEOUT)
}

/// [`fwe`] with a time limit of `limit`.
fn fwe_within(program: &Path, args: &[&str], limit: Duration) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fwe"));
    cmd.arg("--strace").arg(program).args(args).env("FWE_GUEST_VAR", "from-host");
    let out = run_vm_bounded_for(cmd, limit);
    // Shown when a test fails.
    eprintln!("--- {} stderr:\n{}", program.display(), String::from_utf8_lossy(&out.stderr));
    out
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The root filesystem: an assembly guest writes `/probe` under a `--root`
/// directory, which must land in the host directory and nowhere else.
#[test]
fn root_filesystem_confines_writes() {
    for name in ["fileio", "fileio-pie"] {
        let root = std::env::temp_dir().join(format!("fwe-root-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_fwe"));
        cmd.arg("--strace").arg("--root").arg(&root).arg(asm_guest(name));
        let out = run_bounded(cmd);
        eprintln!("--- {name} stderr:\n{}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(out.status.code(), Some(0), "{name}");
        assert_eq!(std::fs::read(root.join("probe")).unwrap(), b"ok\n", "{name}");
        let _ = std::fs::remove_dir_all(&root);
    }
}

/// Build one assembly guest object and link it with the given extra flags.
fn build_asm(name: &str, link_args: &[&str]) -> PathBuf {
    let out = out_dir().join("asm");
    std::fs::create_dir_all(&out).unwrap();
    let obj = out.join(format!("{name}.o"));
    run_checked(
        Command::new("clang")
            .args(["--target=aarch64-linux-gnu", "-c", "-o"])
            .arg(&obj)
            .arg(repo().join("guests/asm").join(format!("{name}.S"))),
    );
    let bin = out.join(name);
    let mut cmd = Command::new(rust_lld());
    cmd.args(["-flavor", "gnu"]).args(link_args).arg("-o").arg(&bin).arg(&obj);
    run_checked(&mut cmd);
    bin
}

/// A vendored real libc the dynamic C guests are built and run against.
#[derive(Clone, Copy)]
enum Libc {
    /// musl: the dynamic linker is itself the shared libc, one self-contained
    /// file (`guests/musl`).
    Musl,
    /// glibc: a separate dynamic linker and shared libc, so the linker maps
    /// `libc.so.6` itself at run time (`guests/glibc`).
    Glibc,
}

impl Libc {
    fn lib_dir(self) -> PathBuf {
        repo().join(match self {
            Libc::Musl => "guests/musl/lib",
            Libc::Glibc => "guests/glibc/lib",
        })
    }

    /// The interpreter path the guest names via PT_INTERP.
    fn interp(self) -> &'static str {
        match self {
            Libc::Musl => "/lib/ld-musl-aarch64.so.1",
            Libc::Glibc => "/lib/ld-linux-aarch64.so.1",
        }
    }

    /// The shared libc object to link the guests against.
    fn libc_so(self) -> PathBuf {
        self.lib_dir().join(match self {
            Libc::Musl => "ld-musl-aarch64.so.1",
            Libc::Glibc => "libc.so.6",
        })
    }
}

/// Build one C guest and link it as a dynamic PIE against the given real libc.
/// With `crt`, the libc's C-runtime startup objects are linked in (for a guest
/// with a normal `main`); without them the guest provides its own `_start`.
/// The guest is compiled freestanding with no host headers, like the assembly
/// guests, so only a bare cross `clang` is needed.
fn build_c_dynamic(name: &str, libc: Libc, crt: bool) -> PathBuf {
    build_c(name, libc, crt, true)
}

/// Like [`build_c_dynamic`], but a non-PIE `ET_EXEC` at the linker's default
/// low address, as distributions build some programs (Debian's `python3`):
/// only the hypervisor backend can run it.
fn build_c(name: &str, libc: Libc, crt: bool, pie: bool) -> PathBuf {
    build_c_as(name, libc, crt, pie, false)
}

/// [`build_c`] for a debugger: unoptimized, with debug information
/// (`-O0 -g`).
fn build_c_debug(name: &str, libc: Libc) -> PathBuf {
    build_c_as(name, libc, true, true, true)
}

fn build_c_as(name: &str, libc: Libc, crt: bool, pie: bool, debug: bool) -> PathBuf {
    let out = out_dir().join("c");
    std::fs::create_dir_all(&out).unwrap();
    let mut tag =
        if pie { name_suffix(libc).to_string() } else { format!("{}-nopie", name_suffix(libc)) };
    if debug {
        tag.push_str("-g");
    }
    let obj = out.join(format!("{name}-{tag}.o"));
    run_checked(
        Command::new("clang")
            .args(if debug { &["-O0", "-g"][..] } else { &["-O2"][..] })
            .args([
                "--target=aarch64-linux-gnu",
                "-fno-stack-protector",
                if pie { "-fPIC" } else { "-fno-pic" },
                "-ffreestanding",
                "-c",
                "-o",
            ])
            .arg(&obj)
            .arg(repo().join("guests/c").join(format!("{name}.c"))),
    );
    let bin = out.join(format!("{name}-{tag}"));
    let lib = libc.lib_dir();
    let interp = format!("--dynamic-linker={}", libc.interp());
    let mut cmd = Command::new(rust_lld());
    cmd.args(["-flavor", "gnu"]);
    if pie {
        cmd.arg("-pie");
    }
    cmd.arg(&interp);
    // A run-time search path so the glibc linker finds libc.so.6 in the
    // rootfs's /lib; harmless for musl, whose interpreter is the libc itself.
    cmd.args(["-rpath=/lib", "-o"]).arg(&bin);
    if crt {
        cmd.arg(lib.join("Scrt1.o")).arg(lib.join("crti.o"));
    }
    // Linking against the shared libc records a NEEDED of its soname, which
    // the interpreter satisfies (musl from itself, glibc by mapping libc.so.6).
    cmd.arg(&obj).arg(libc.libc_so());
    if crt {
        if matches!(libc, Libc::Glibc) {
            // glibc links a small static companion beside the shared libc.
            cmd.arg(lib.join("libc_nonshared.a"));
        }
        cmd.arg(lib.join("crtn.o"));
    }
    run_checked(&mut cmd);
    bin
}

fn name_suffix(libc: Libc) -> &'static str {
    match libc {
        Libc::Musl => "musl",
        Libc::Glibc => "glibc",
    }
}

/// A temporary root filesystem holding the libc's dynamic linker (and, for
/// glibc, the shared libc) at the paths the guests expect.
fn libc_rootfs(libc: Libc, tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("fwe-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("lib")).unwrap();
    let lib = libc.lib_dir();
    match libc {
        Libc::Musl => {
            std::fs::copy(lib.join("ld-musl-aarch64.so.1"), root.join("lib/ld-musl-aarch64.so.1"))
                .unwrap();
        }
        Libc::Glibc => {
            std::fs::copy(
                lib.join("ld-linux-aarch64.so.1"),
                root.join("lib/ld-linux-aarch64.so.1"),
            )
            .unwrap();
            std::fs::copy(lib.join("libc.so.6"), root.join("lib/libc.so.6")).unwrap();
            std::fs::copy(lib.join("libm.so.6"), root.join("lib/libm.so.6")).unwrap();
        }
    }
    root
}

/// A shared glibc root filesystem for running the vendored Debian programs:
/// the dynamic linker and shared libc under `/lib`, plus the extra shared
/// libraries the programs need (e.g. `ls` → `libselinux` → `libpcre2`), built
/// once.
fn debian_root() -> &'static Path {
    static ROOT: OnceLock<PathBuf> = OnceLock::new();
    ROOT.get_or_init(|| {
        let root = libc_rootfs(Libc::Glibc, "debian");
        for entry in std::fs::read_dir(repo().join("guests/debian/lib")).unwrap() {
            let entry = entry.unwrap();
            std::fs::copy(entry.path(), root.join("lib").join(entry.file_name())).unwrap();
        }
        root
    })
}

/// A vendored Debian coreutils program (see `guests/debian/README.md`).
fn debian_bin(name: &str) -> PathBuf {
    repo().join("guests/debian/bin").join(name)
}

/// Run a vendored Debian program under `fwe` against the glibc root
/// filesystem, feeding `input` to its standard input. `LD_LIBRARY_PATH` points
/// the dynamic linker at the shared libc in the rootfs's `/lib`.
fn run_debian(name: &str, args: &[&str], input: &[u8]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fwe"));
    cmd.arg("--strace")
        .arg("--root")
        .arg(debian_root())
        .arg(debian_bin(name))
        .args(args)
        .env_clear()
        .env("LD_LIBRARY_PATH", "/lib")
        .env("HOME", "/")
        .env("PATH", "/bin")
        .env("FOO", "bar");
    let out = run_bounded_with_stdin(cmd, input);
    eprintln!("--- debian {name} stderr:\n{}", String::from_utf8_lossy(&out.stderr));
    out
}

/// Synthetic /proc: a guest reads /proc/sys/kernel/ostype and gets "Linux".
#[test]
fn reads_synthetic_proc() {
    for name in ["procread", "procread-pie"] {
        assert_eq!(fwe(&asm_guest(name), &[]).status.code(), Some(0), "{name}");
    }
}

/// epoll: a guest registers a pipe's read end for EPOLLIN, writes a byte, and
/// `epoll_pwait` returns exactly one event carrying EPOLLIN and the registered
/// data word. Exercises the kqueue translation on macOS and passthrough on
/// Linux end to end.
#[test]
fn epoll_round_trip() {
    for name in ["epolltest", "epolltest-pie"] {
        assert_eq!(fwe(&asm_guest(name), &[]).status.code(), Some(0), "{name}");
    }
}

/// eventfd: a guest registers a non-blocking eventfd in epoll, confirms it is
/// not ready at count 0, writes 5, sees epoll report it readable with the
/// registered data, and reads the counter back as 5. Covers the pipe-backed
/// counter emulation on macOS and passthrough on Linux.
#[test]
fn eventfd_through_epoll() {
    for name in ["eventfdtest", "eventfdtest-pie"] {
        assert_eq!(fwe(&asm_guest(name), &[]).status.code(), Some(0), "{name}");
    }
}

/// timerfd: a guest arms a one-shot timer, blocks in `read`, and gets at least
/// one expiration. Covers the kqueue-timer emulation on macOS and passthrough
/// on Linux.
#[test]
fn timerfd_fires() {
    for name in ["timerfdtest", "timerfdtest-pie"] {
        assert_eq!(fwe(&asm_guest(name), &[]).status.code(), Some(0), "{name}");
    }
}

/// sockets: a guest creates a connected AF_UNIX stream pair with `socketpair`
/// and passes a message through it, exercising the socket syscall path end to
/// end (socketpair on macOS applies the type flags and translates the family).
#[test]
fn socketpair_message() {
    for name in ["socketpairtest", "socketpairtest-pie"] {
        assert_eq!(fwe(&asm_guest(name), &[]).status.code(), Some(0), "{name}");
    }
}

/// synthetic directory listing: a guest opens `/proc` and finds the `cpuinfo`
/// entry via `getdents64`, exercising the synthetic directory fd.
#[test]
fn lists_proc_directory() {
    for name in ["procdir", "procdir-pie"] {
        assert_eq!(fwe(&asm_guest(name), &[]).status.code(), Some(0), "{name}");
    }
}

/// credentials: starting as virtual root, a guest drops to uid 1000, confirms
/// `getuid`/`geteuid` report it, and confirms it can no longer regain root.
#[test]
fn virtual_credentials() {
    for name in ["credtest", "credtest-pie"] {
        assert_eq!(fwe(&asm_guest(name), &[]).status.code(), Some(0), "{name}");
    }
}

/// signalfd: a guest blocks SIGUSR1, creates a signalfd for it, raises it, and
/// reads the queued `signalfd_siginfo` back, exercising the virtual-signal to
/// signalfd path end to end.
#[test]
fn signalfd_delivers() {
    for name in ["signalfdtest", "signalfdtest-pie"] {
        assert_eq!(fwe(&asm_guest(name), &[]).status.code(), Some(0), "{name}");
    }
}

/// job control: a forked child starts a new session with `setsid` and confirms
/// `getsid(0)` and `getpgid(0)` agree, exercising the session/process-group
/// syscalls end to end.
#[test]
fn session_and_process_groups() {
    for name in ["jobctl", "jobctl-pie"] {
        assert_eq!(fwe(&asm_guest(name), &[]).status.code(), Some(0), "{name}");
    }
}

/// fork and wait: a guest forks, the child exits 7, and the parent reaps it
/// and exits with the child's decoded `WEXITSTATUS` — so a passing run (7)
/// confirms the whole fork/exit/wait path and the Linux status encoding.
#[test]
fn fork_and_wait() {
    for name in ["forktest", "forktest-pie"] {
        assert_eq!(fwe(&asm_guest(name), &[]).status.code(), Some(7), "{name}");
    }
}

/// execve: a guest replaces its image with a second program (from the rootfs)
/// and the new program runs, finding the descriptor its predecessor left open
/// and not the one it marked close-on-exec.
#[test]
fn execve_replaces_program() {
    let root = std::env::temp_dir().join(format!("fwe-exec-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::copy(asm_guest("execee-pie"), root.join("execee")).unwrap();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fwe"));
    cmd.arg("--strace").arg("--root").arg(&root).arg(asm_guest("execer-pie"));
    let out = run_bounded(cmd);
    eprintln!("--- execer stderr:\n{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(stdout(&out), "exec target ran\n");
    assert_eq!(out.status.code(), Some(0));
    let _ = std::fs::remove_dir_all(&root);
}

/// Threads: a guest clones a child that writes a shared counter and exits;
/// the parent joins via the CLONE_CHILD_CLEARTID futex and checks the counter.
/// `clone3`: a thread made from a `struct clone_args` gets the stack, TLS
/// and tid words it names; a too-small structure is `EINVAL` and a pidfd
/// request `ENOSYS`.
#[test]
fn clone3_makes_a_thread() {
    for name in ["clone3test", "clone3test-pie"] {
        assert_eq!(fwe(&asm_guest(name), &[]).status.code(), Some(0), "{name}");
    }
}

#[test]
fn clone_thread_runs_and_joins() {
    for name in ["threadtest", "threadtest-pie"] {
        assert_eq!(fwe(&asm_guest(name), &[]).status.code(), Some(0), "{name}");
    }
}

/// Signal delivery: a guest installs a SIGUSR1 handler, raises it, and the
/// handler (returning through fwe's rt_sigreturn trampoline) sets a flag the
/// program checks before exiting 0.
#[test]
fn signal_handler_runs() {
    for name in ["sigtest", "sigtest-pie"] {
        assert_eq!(fwe(&asm_guest(name), &[]).status.code(), Some(0), "{name}");
    }
}

/// The dynamic loader: a PIE executable names an interpreter via PT_INTERP;
/// fwe must load the interpreter (from the rootfs) and hand control to it
/// with AT_ENTRY pointing at the executable, which the interpreter jumps to.
#[test]
fn dynamic_loader_hands_off_to_interpreter() {
    let interp = build_asm("interp", &["-pie", "--no-dynamic-linker"]);
    let dynprog = build_asm("dynprog", &["-pie", "--dynamic-linker=/interp"]);

    let root = std::env::temp_dir().join(format!("fwe-dyn-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::copy(&interp, root.join("interp")).unwrap();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fwe"));
    cmd.arg("--strace").arg("--root").arg(&root).arg(&dynprog);
    let out = run_bounded(cmd);
    eprintln!("--- dynprog stderr:\n{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(stdout(&out), "dynamic handoff ok\n");
    assert_eq!(out.status.code(), Some(0));
    let _ = std::fs::remove_dir_all(&root);
}

/// Real dynamic linking, minimal case: a PIE with its own `_start` that calls
/// `write` and `_exit` resolved from a genuine musl shared libc. This drives
/// the real musl dynamic linker end to end — it maps and self-relocates,
/// applies this program's jump-slot relocations against libc, sets up the
/// thread pointer, and transfers control — with no C runtime in the way.
#[test]
fn dynamic_min_resolves_libc_symbols() {
    let prog = build_c_dynamic("dynmin", Libc::Musl, false);
    let root = libc_rootfs(Libc::Musl, "musl-min");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fwe"));
    cmd.arg("--strace").arg("--root").arg(&root).arg(&prog);
    let out = run_bounded(cmd);
    eprintln!("--- dynmin stderr:\n{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(stdout(&out), "dynamic-min: hello from musl\n");
    assert_eq!(out.status.code(), Some(0));
    let _ = std::fs::remove_dir_all(&root);
}

/// Real dynamic linking, full startup: a normal `main` linked through musl's
/// crt objects, using the heap and buffered stdio from the shared libc. Covers
/// the complete path — `ld-musl` self-relocation, `crt` `_start`,
/// `__libc_start_main`, `main`, then `malloc`/`printf` — against a genuine
/// musl build, the way a real dynamically linked program starts.
#[test]
fn dynamic_hello_runs_through_musl_startup() {
    let prog = build_c_dynamic("dynhello", Libc::Musl, true);
    let root = libc_rootfs(Libc::Musl, "musl-hello");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fwe"));
    cmd.arg("--strace").arg("--root").arg(&root).arg(&prog).arg("fun-with-emulators");
    let out = run_bounded(cmd);
    eprintln!("--- dynhello stderr:\n{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(stdout(&out), "dynamic hello, fun-with-emulators\n");
    assert_eq!(out.status.code(), Some(0));
    let _ = std::fs::remove_dir_all(&root);
}

/// Real glibc dynamic linking, minimal case: a PIE with its own `_start`
/// calling only `_exit` (a plain syscall wrapper, so no thread-control-block
/// setup is needed). glibc's dynamic linker is a separate object from the
/// shared libc, so this drives the path musl never did: load `ld-linux`, have
/// it map `libc.so.6` itself at run time (translated through the section-aware
/// `mmap` path, since libc.so.6's code segment also holds its symbol and
/// string tables), resolve `_exit`, and hand off.
#[test]
fn dynamic_glibc_exit_maps_shared_libc() {
    let prog = build_c_dynamic("dynexit", Libc::Glibc, false);
    let root = libc_rootfs(Libc::Glibc, "glibc-exit");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fwe"));
    cmd.arg("--strace").arg("--root").arg(&root).arg(&prog);
    let out = run_bounded(cmd);
    eprintln!("--- dynexit(glibc) stderr:\n{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(42));
    let _ = std::fs::remove_dir_all(&root);
}

/// Real glibc dynamic linking, full startup: a normal `main` linked through
/// glibc's crt objects, using the heap and buffered stdio from the shared
/// libc. Covers the complete path — `ld-linux` maps and relocates `libc.so.6`,
/// crt `_start`, `__libc_start_main` (thread-control-block and TLS setup),
/// `main`, then `malloc`/`printf` — against a genuine glibc, the way a Debian
/// program starts.
#[test]
fn dynamic_glibc_hello_runs_through_libc_startup() {
    let prog = build_c_dynamic("dynhello", Libc::Glibc, true);
    let root = libc_rootfs(Libc::Glibc, "glibc-hello");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fwe"));
    cmd.arg("--strace").arg("--root").arg(&root).arg(&prog).arg("fun-with-emulators");
    let out = run_bounded(cmd);
    eprintln!("--- dynhello(glibc) stderr:\n{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(stdout(&out), "dynamic hello, fun-with-emulators\n");
    assert_eq!(out.status.code(), Some(0));
    let _ = std::fs::remove_dir_all(&root);
}

/// Real Debian coreutils: unmodified glibc programs from a Debian rootfs run
/// and produce correct output. These are genuine distribution binaries, not
/// built here — the whole chain (glibc dynamic linking, process startup, file
/// and terminal syscalls, exit status) has to work for them to behave.
#[test]
fn debian_coreutils_true_and_false_exit_status() {
    assert_eq!(run_debian("true", &[], &[]).status.code(), Some(0));
    assert_eq!(run_debian("false", &[], &[]).status.code(), Some(1));
}

#[test]
fn debian_coreutils_echo_prints_arguments() {
    let out = run_debian("echo", &["hello", "world"], &[]);
    assert_eq!(stdout(&out), "hello world\n");
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn debian_coreutils_seq_counts() {
    let out = run_debian("seq", &["1", "5"], &[]);
    assert_eq!(stdout(&out), "1\n2\n3\n4\n5\n");
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn debian_coreutils_env_shows_environment() {
    let out = run_debian("env", &[], &[]);
    assert!(stdout(&out).lines().any(|l| l == "FOO=bar"), "env output: {:?}", stdout(&out));
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn debian_coreutils_cat_echoes_stdin() {
    let out = run_debian("cat", &[], b"one\ntwo\n");
    assert_eq!(stdout(&out), "one\ntwo\n");
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn debian_coreutils_sort_orders_lines() {
    let out = run_debian("sort", &[], b"banana\napple\ncherry\n");
    assert_eq!(stdout(&out), "apple\nbanana\ncherry\n");
    assert_eq!(out.status.code(), Some(0));
}

/// Real Debian `ls`: a program with a transitive shared-library graph
/// (`ls` → `libselinux` → `libpcre2`, plus `libc`). The dynamic linker must
/// find and map each library from the rootfs, resolving one against another,
/// before `ls` lists a directory. With output to a pipe, GNU `ls` prints one
/// sorted name per line.
#[test]
fn debian_coreutils_ls_lists_directory() {
    // A directory with known contents inside the shared rootfs.
    let dir = debian_root().join("lsdir");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for name in ["alpha", "beta", "gamma"] {
        std::fs::write(dir.join(name), b"x").unwrap();
    }
    let out = run_debian("ls", &["/lsdir"], &[]);
    assert_eq!(stdout(&out), "alpha\nbeta\ngamma\n");
    assert_eq!(out.status.code(), Some(0));
}

/// Real Debian bash (run with `-c`, non-interactively): the shell itself, a
/// large glibc program linked against libtinfo. It has to start up, parse, and
/// run builtins, arithmetic and loops in the shell process — covering far more
/// of libc than the coreutils programs do.
#[test]
fn debian_bash_runs_a_command() {
    let out = run_debian("bash", &["-c", "echo hello world"], &[]);
    assert_eq!(stdout(&out), "hello world\n");
    assert_eq!(out.status.code(), Some(0));
}

/// Debian's git, the first of M2's target programs, driven by Debian's bash
/// inside the guest: a repository is created, committed to on two branches,
/// merged, stashed, rebased, searched (`git grep` compiles its pattern with
/// PCRE2's JIT, so code written to writable and executable memory runs),
/// blamed, packed with `gc` and cloned over `file://` (through `/bin/sh` and
/// `git-upload-pack`). Every object name is fixed by the dates, and each
/// matches what git on the host makes of the same steps.
#[test]
fn debian_git_runs_a_workflow() {
    let _workload = workload();
    let root = std::env::temp_dir().join(format!("fwe-git-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    for dir in ["lib", "bin", "usr/bin", "usr/lib/git-core", "home/u"] {
        std::fs::create_dir_all(root.join(dir)).unwrap();
    }
    for entry in std::fs::read_dir(debian_root().join("lib")).unwrap() {
        let entry = entry.unwrap();
        std::fs::copy(entry.path(), root.join("lib").join(entry.file_name())).unwrap();
    }
    std::fs::copy(debian_bin("bash"), root.join("bin/bash")).unwrap();
    std::fs::copy(debian_bin("git"), root.join("usr/bin/git")).unwrap();
    // As Debian installs them: the shell, and git's helpers as links to git.
    std::os::unix::fs::symlink("bash", root.join("bin/sh")).unwrap();
    std::os::unix::fs::symlink("../../bin/git", root.join("usr/lib/git-core/git")).unwrap();
    std::os::unix::fs::symlink("git", root.join("usr/lib/git-core/git-upload-pack")).unwrap();

    let script = r#"
        set -e
        export HOME=/home/u GIT_CONFIG_NOSYSTEM=1
        export GIT_AUTHOR_DATE=2026-01-01T00:00:00Z GIT_COMMITTER_DATE=2026-01-01T00:00:00Z
        cd /home/u
        git init -q -b main repo
        cd repo
        git config user.name Tester
        git config user.email t@example.com
        printf 'one
two
three
' > a.txt
        git add a.txt
        git commit -q -m first
        git switch -q -c feature
        printf 'one
two
three
four
' > a.txt
        git commit -q -am 'feature: four'
        git switch -q main
        printf 'zero
one
two
three
' > a.txt
        git commit -q -am 'main: zero'
        git merge -q --no-edit feature
        git log --graph --format='%h %s'
        git tag v1
        echo scratch >> a.txt
        git stash -q
        git stash list
        git stash pop -q
        git checkout -q -- a.txt
        git rebase -q HEAD~1
        git grep -n two
        git blame -s a.txt
        git gc -q
        git fsck --no-progress --no-dangling
        cd ..
        git clone -q file:///home/u/repo clone
        git -C clone log --format='%h %s'
        git -C clone status --short --branch
    "#;
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fwe"));
    cmd.arg("--root")
        .arg(&root)
        .arg(root.join("bin/bash"))
        .args(["-c", script])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null());
    // About 20 s alone: git's commands start many git processes, each a
    // fresh fwe that prepares the 3.7 MB binary's code.
    let out = run_bounded_for(cmd, &[], Duration::from_secs(60));
    eprintln!("--- git stderr:\n{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(
        stdout(&out),
        "Auto-merging a.txt\n\
         *   add5a56 Merge branch 'feature'\n\
         |\\  \n\
         | * 032b22c feature: four\n\
         * | c45f3f2 main: zero\n\
         |/  \n\
         * fc2d461 first\n\
         stash@{0}: WIP on main: add5a56 Merge branch 'feature'\n\
         a.txt:3:two\n\
         c45f3f2b 1) zero\n\
         ^fc2d461 2) one\n\
         ^fc2d461 3) two\n\
         ^fc2d461 4) three\n\
         2586db8f 5) four\n\
         2586db8 feature: four\n\
         c45f3f2 main: zero\n\
         fc2d461 first\n\
         ## main...origin/main\n"
    );
    assert_eq!(out.status.code(), Some(0));
    let _ = std::fs::remove_dir_all(&root);
}

/// A root filesystem of its own for one Debian program's test (`tag`): the
/// shared libraries, bash as `/bin/sh` and `/bin/bash`, and the `dirs` the
/// test needs. Removed when dropped.
struct ProgramRoot(PathBuf);

impl ProgramRoot {
    fn new(tag: &str, dirs: &[&str]) -> Self {
        let root = std::env::temp_dir().join(format!("fwe-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for dir in ["lib", "bin", "tmp"].iter().chain(dirs) {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }
        for entry in std::fs::read_dir(debian_root().join("lib")).unwrap() {
            let entry = entry.unwrap();
            std::fs::copy(entry.path(), root.join("lib").join(entry.file_name())).unwrap();
        }
        std::fs::copy(debian_bin("bash"), root.join("bin/bash")).unwrap();
        std::os::unix::fs::symlink("bash", root.join("bin/sh")).unwrap();
        ProgramRoot(root)
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.0.join(rel)
    }

    /// `fwe` running `program` (a path inside the root) with a clean
    /// environment.
    fn command(&self, program: &str) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_fwe"));
        cmd.arg("--root")
            .arg(&self.0)
            .arg(self.path(program.trim_start_matches('/')))
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/tmp")
            .stdin(Stdio::null());
        cmd
    }
}

impl Drop for ProgramRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Debian's SQLite, the first of M2's databases: a write-ahead-logged
/// database (its index shared between processes through a `MAP_SHARED`
/// mapping) with three processes inserting at once under `fcntl` locks,
/// then full-text search, a recursive query, JSON, an integrity check and
/// the schema.
#[test]
fn debian_sqlite_runs_a_database() {
    let _workload = workload();
    let root = ProgramRoot::new("sqlite", &[]);
    std::fs::copy(debian_bin("sqlite3"), root.path("bin/sqlite3")).unwrap();
    std::fs::copy(debian_bin("seq"), root.path("bin/seq")).unwrap();
    let script = r#"
        set -e
        cd /tmp
        sqlite3 db <<'SQL'
pragma journal_mode=wal;
create table kv(k integer primary key, v text not null unique);
create virtual table docs using fts5(body);
insert into docs values ('the quick brown fox'), ('lazy dogs sleep'), ('quick thinking');
SQL
        for w in 1 2 3; do
            (for i in $(seq 1 8); do
                sqlite3 -cmd '.timeout 10000' db "insert into kv(v) values ('w$w-$i')"
            done) &
        done
        wait
        sqlite3 db "select count(*), count(distinct substr(v, 1, 2)) from kv"
        sqlite3 db "select rowid from docs where docs match 'quick' order by rowid"
        sqlite3 db "with recursive c(x) as (select 1 union all select x + 1 from c where x < 10)
                    select group_concat(x * x) from c"
        sqlite3 db "select json_object('a', 1, 'b', json_array(2, 3))"
        sqlite3 db "pragma integrity_check"
        sqlite3 db "select sql from sqlite_schema where name = 'kv'"
    "#;
    let mut cmd = root.command("/bin/bash");
    cmd.args(["-c", script]);
    // Each sqlite3 is a fresh fwe preparing the 1.5 MB library's code.
    let out = run_bounded_for(cmd, &[], Duration::from_secs(60));
    eprintln!("--- sqlite stderr:\n{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(
        stdout(&out),
        "wal\n\
         24|3\n\
         1\n\
         3\n\
         1,4,9,16,25,36,49,64,81,100\n\
         {\"a\":1,\"b\":[2,3]}\n\
         ok\n\
         CREATE TABLE kv(k integer primary key, v text not null unique)\n"
    );
    assert_eq!(out.status.code(), Some(0));
}

/// Where fetched packages are cached (`FWE_FETCH_CACHE`, or under
/// `target/`), so a test downloads each only once.
fn fetch_cache() -> PathBuf {
    std::env::var_os("FWE_FETCH_CACHE")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo().join("target/fetched-packages"))
}

/// The files listed in `guests/<distro>/fetch/<manifest>.txt` (paths and
/// SHA-256s), and the manifest's text.
fn manifest_in(distro: &str, manifest: &str) -> (String, Vec<(String, String)>) {
    let list =
        std::fs::read_to_string(repo().join(format!("guests/{distro}/fetch/{manifest}.txt")))
            .unwrap();
    let packages = list
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| l.split_once(' ').unwrap())
        .map(|(p, h)| (p.to_string(), h.to_string()))
        .collect();
    (list, packages)
}

fn manifest(manifest: &str) -> (String, Vec<(String, String)>) {
    manifest_in("debian", manifest)
}

fn sha256(f: &Path) -> String {
    let out = Command::new("shasum").args(["-a", "256"]).arg(f).output().unwrap();
    String::from_utf8_lossy(&out.stdout).split_whitespace().next().unwrap_or("").to_string()
}

/// A file fetched from the first of `urls` that serves it with SHA-256
/// `sha256`, cached under `name`.
fn fetch_pinned(name: &str, urls: &[String], sha256_hex: &str, tag: &str) -> PathBuf {
    let cache = fetch_cache();
    std::fs::create_dir_all(&cache).unwrap();
    let file = cache.join(name);
    if file.exists() && sha256(&file) == sha256_hex {
        return file;
    }
    // Tests fetch at once, and manifests share packages: each download goes
    // to a name of its own and is renamed into place once it checks out.
    // (A name of this fetch's own: two tests may fetch the same file.)
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let part = cache.join(format!("{name}.{tag}.{}-{n}.part", std::process::id()));
    let fetched = urls.iter().any(|url| {
        Command::new("curl")
            .args(["-fsSL", "--retry", "3", "-o"])
            .arg(&part)
            .arg(url)
            .status()
            .is_ok_and(|s| s.success())
            && sha256(&part) == sha256_hex
    });
    assert!(fetched, "could not fetch {name} with SHA-256 {sha256_hex} from {urls:?}");
    std::fs::rename(&part, &file).unwrap();
    file
}

/// The `.deb` files a manifest lists, fetched on first use and checked
/// against the SHA-256 recorded there. They come from deb.debian.org, or
/// from snapshot.debian.org once a newer version has replaced them.
fn fetched_debs(manifest_name: &str) -> Vec<PathBuf> {
    let (_, packages) = manifest(manifest_name);
    packages
        .iter()
        .map(|(pool, sha256)| {
            let name = Path::new(pool).file_name().unwrap().to_string_lossy().into_owned();
            let urls = [
                format!("https://deb.debian.org/debian/{pool}"),
                format!("https://snapshot.debian.org/archive/debian/20261101T000000Z/{pool}"),
            ];
            fetch_pinned(&name, &urls, sha256, manifest_name)
        })
        .collect()
}

/// A root filesystem of the packages `manifest` lists ([`fetched_debs`]),
/// unpacked once and cached, plus the vendored glibc runtime and bash.
fn fetched_root(manifest_name: &str) -> PathBuf {
    let (list, _) = manifest(manifest_name);
    let cache = fetch_cache();
    let root = cache.join(format!("root-{manifest_name}"));
    let done = root.join(".fwe-complete");
    if std::fs::read_to_string(&done).ok().as_deref() == Some(list.as_str()) {
        return root;
    }
    let debs = fetched_debs(manifest_name);
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("lib")).unwrap();
    for deb in &debs {
        // A .deb is an `ar` archive whose data.tar.* holds the files.
        let unpack = cache.join(format!("unpack-{manifest_name}"));
        let _ = std::fs::remove_dir_all(&unpack);
        std::fs::create_dir_all(&unpack).unwrap();
        run_checked(Command::new("ar").arg("x").arg(deb).current_dir(&unpack));
        let data = std::fs::read_dir(&unpack)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.file_name().unwrap().to_string_lossy().starts_with("data.tar"))
            .unwrap();
        run_checked(Command::new("tar").arg("xf").arg(&data).arg("-C").arg(&root));
    }
    for name in ["ld-linux-aarch64.so.1", "libc.so.6", "libm.so.6"] {
        std::fs::copy(repo().join("guests/glibc/lib").join(name), root.join("lib").join(name))
            .unwrap();
    }
    std::fs::copy(repo().join("guests/debian/lib/libtinfo.so.6"), root.join("lib/libtinfo.so.6"))
        .unwrap();
    std::fs::create_dir_all(root.join("bin")).unwrap();
    std::fs::create_dir_all(root.join("tmp")).unwrap();
    std::fs::copy(debian_bin("bash"), root.join("bin/bash")).unwrap();
    let _ = std::os::unix::fs::symlink("bash", root.join("bin/sh"));
    std::fs::write(&done, &list).unwrap();
    root
}

/// The files an Alpine manifest (`guests/alpine/fetch/<manifest>.txt`)
/// lists, fetched from dl-cdn.alpinelinux.org on first use and checked
/// against their SHA-256s.
fn fetched_alpine(manifest_name: &str) -> Vec<PathBuf> {
    let (_, files) = manifest_in("alpine", manifest_name);
    files
        .iter()
        .map(|(path, sha256)| {
            let name = format!("alpine-{}", Path::new(path).file_name().unwrap().to_string_lossy());
            let urls = [format!("https://dl-cdn.alpinelinux.org/alpine/{path}")];
            fetch_pinned(&name, &urls, sha256, manifest_name)
        })
        .collect()
}

/// A root filesystem of what an Alpine manifest lists, unpacked in order
/// and cached: the minirootfs, then each package. An `.apk` is gzipped tar
/// segments, its signature and metadata (dot files) before the files.
fn alpine_root(manifest_name: &str) -> PathBuf {
    // One test at a time makes a root: two may want the same one.
    static MAKING: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _making = MAKING.lock().unwrap_or_else(|e| e.into_inner());
    let (list, _) = manifest_in("alpine", manifest_name);
    let root = fetch_cache().join(format!("alpine-root-{manifest_name}"));
    let done = root.join(".fwe-complete");
    if std::fs::read_to_string(&done).ok().as_deref() == Some(list.as_str()) {
        return root;
    }
    let files = fetched_alpine(manifest_name);
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    for f in &files {
        run_checked(
            // With the files' extended attributes: a program's file
            // capabilities (`security.capability`) among them.
            Command::new("tar")
                .arg("--xattrs")
                .arg("-xzf")
                .arg(f)
                .args(["--exclude", ".PKGINFO", "--exclude", ".SIGN.*", "--exclude", ".pre-*"])
                .args(["--exclude", ".post-*", "--exclude", ".trigger", "-C"])
                .arg(&root),
        );
    }
    std::fs::write(&done, &list).unwrap();
    root
}

/// The minirootfs of an Alpine manifest: the standard `alpine` image's
/// root filesystem, for a container to run.
fn alpine_image(manifest_name: &str) -> PathBuf {
    fetched_alpine(manifest_name)
        .into_iter()
        .find(|f| f.to_string_lossy().contains("minirootfs"))
        .unwrap()
}

/// Whether the tests of fetched programs that `var` gates run: they run
/// only where it is set (CI's own job for them), not on a development
/// machine.
fn fetched_program_tests(var: &str) -> bool {
    let on = std::env::var_os(var).is_some();
    if !on {
        eprintln!("skipped: set {var}=1 to run them");
    }
    on
}

/// Whether the debugger tests run: they need Alpine's strace and gdb
/// (fetched: `guests/alpine/fetch/ptrace.txt`), run only where
/// `FWE_DEBUGGER_TESTS` is set (CI's `debuggers` job).
fn debugger_tests() -> bool {
    fetched_program_tests("FWE_DEBUGGER_TESTS")
}

/// Run `args` (a program of the root, then its arguments) in a copy of the
/// `ptrace` manifest's Alpine root, with `/prog` the given program, if
/// any: its output, and the root's file `keep` (if any) as it was left.
fn in_debugger_root(args: &[&str], prog: Option<&Path>, keep: Option<&str>) -> (Output, Vec<u8>) {
    let root = std::env::temp_dir().join(format!(
        "fwe-dbg-{}-{}",
        std::process::id(),
        args[0].replace('/', "-")
    ));
    let _ = std::fs::remove_dir_all(&root);
    run_checked(Command::new("cp").arg("-cR").arg(alpine_root("ptrace")).arg(&root));
    if let Some(p) = prog {
        std::fs::copy(p, root.join("prog")).unwrap();
    }
    let _workload = workload();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fwe"));
    cmd.arg("--root").arg(&root).arg("--cwd").arg("/tmp");
    cmd.arg(root.join(args[0].trim_start_matches('/'))).args(&args[1..]);
    // The environment of a Linux login, not the host's.
    cmd.env_clear().env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin").env("HOME", "/root");
    cmd.env("TERM", "dumb").env("SHELL", "/bin/sh");
    let out = run_bounded_for(cmd, &[], Duration::from_secs(180));
    let kept = keep.and_then(|k| std::fs::read(root.join(k.trim_start_matches('/'))).ok());
    let _ = std::fs::remove_dir_all(&root);
    eprintln!("--- {args:?} stderr:\n{}", String::from_utf8_lossy(&out.stderr));
    (out, kept.unwrap_or_default())
}

/// Alpine's strace (fetched) traces a shell and what it runs (`-f`): the
/// calls with their arguments as Linux's strace shows them, the child's
/// `execve`, and both ends.
#[test]
fn alpine_strace_traces_a_program() {
    if !debugger_tests() {
        return;
    }
    let (out, trace) = in_debugger_root(
        &["/usr/bin/strace", "-f", "-o", "/tmp/trace", "/bin/sh", "-c", "echo hi; /bin/true"],
        None,
        Some("/tmp/trace"),
    );
    let trace = String::from_utf8_lossy(&trace);
    eprintln!("--- trace:\n{trace}");
    assert_eq!(stdout(&out), "hi\n");
    assert_eq!(out.status.code(), Some(0));
    for want in [
        "execve(\"/bin/sh\", [\"/bin/sh\", \"-c\", \"echo hi; /bin/true\"]",
        "execve(\"/bin/true\", [\"/bin/true\"]",
        "+++ exited with 0 +++",
    ] {
        assert!(trace.contains(want), "no {want:?} in the trace");
    }
    // (strace pads the result into a column.)
    let write = trace.lines().find(|l| l.contains("write(1, \"hi\\n\", 3)"));
    assert!(write.is_some_and(|l| l.ends_with("= 3")), "no write of \"hi\" in the trace");
}

/// Alpine's gdb (fetched) debugs a C program built with debug
/// information: a breakpoint on a function stops it there with its
/// arguments, the backtrace names its caller, `finish` returns its value,
/// and the program runs on to its end.
#[test]
fn alpine_gdb_debugs_a_program() {
    if !debugger_tests() {
        return;
    }
    let prog = build_c_debug("debuggee", Libc::Musl);
    let (out, _) = in_debugger_root(
        &[
            "/usr/bin/gdb",
            "-nx",
            "-batch",
            "-ex",
            "break add",
            "-ex",
            "run",
            "-ex",
            "bt",
            "-ex",
            "print a",
            "-ex",
            "print b",
            "-ex",
            "finish",
            "-ex",
            "delete",
            "-ex",
            "continue",
            "/prog",
        ],
        Some(&prog),
        None,
    );
    let text = stdout(&out);
    for want in [
        "Breakpoint 1, add (a=0, b=1) at",
        "in main () at",
        "$1 = 0",
        "$2 = 1",
        "#1  0x",
        "Value returned is $3 = 1",
        "total 6",
        "exited normally]",
    ] {
        assert!(text.contains(want), "no {want:?} in gdb's output ({}):\n{text}", out.status);
    }
}

/// What the container prints in [`alpine_crun_runs_an_image`].
const IN_CONTAINER: &str = "echo pid $$ host $(hostname); cat /proc/self/cgroup; \
    ls /proc | grep -E '^[0-9]+$' | head -1; grep -E 'CapEff|NoNewPrivs|Seccomp:' /proc/self/status; \
    touch /x 2>&1 | sed 's/.*: //'; mkdir /dev/shm/d 2>&1 | sed 's/.*: //'; echo $(ls /dev); \
    echo $(awk '{print $5}' /proc/self/mountinfo); cat /etc/alpine-release";

/// Alpine's crun (fetched: `guests/alpine/fetch/crun.txt`) runs the
/// standard `alpine` image from the spec it writes itself, with a seccomp
/// profile added: in its own pid, network, IPC, UTS, cgroup and mount
/// namespaces, on a read-only root with the mounts and devices the spec
/// names, with the capabilities it keeps, `no_new_privs`, and the profile
/// refusing `mkdirat`.
#[test]
fn alpine_crun_runs_an_image() {
    let root = std::env::temp_dir().join(format!("fwe-crun-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    run_checked(Command::new("cp").arg("-cR").arg(alpine_root("crun")).arg(&root));
    let bundle = root.join("bundle");
    std::fs::create_dir_all(bundle.join("rootfs")).unwrap();
    run_checked(
        Command::new("tar")
            .arg("xzf")
            .arg(alpine_image("crun"))
            .arg("-C")
            .arg(bundle.join("rootfs")),
    );
    let _workload = workload();
    // Traced: the container's run to a file (its program writes its own
    // standard error into what the test reads), for a run that goes wrong.
    let run_trace = root.join("tmp/crun-run.trace");
    let crun = |args: &[&str]| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_fwe"));
        cmd.arg("--root").arg(&root).arg("--cwd").arg("/bundle");
        if args[0] == "run" {
            cmd.arg("--strace").arg(format!("--strace-file={}", run_trace.display()));
        } else {
            cmd.arg("--strace=failures");
        }
        cmd.arg(root.join("usr/bin/crun")).args(args);
        let out = run_bounded_for(cmd, &[], Duration::from_secs(120));
        eprintln!("--- crun {args:?} stderr:\n{}", String::from_utf8_lossy(&out.stderr));
        out
    };
    let out = crun(&["--version"]);
    assert!(stdout(&out).contains("crun version 1.17"), "{}", stdout(&out));
    assert_eq!(crun(&["spec"]).status.code(), Some(0));
    // The spec as crun wrote it, with no terminal, the program to run, and
    // a seccomp profile.
    let config = bundle.join("config.json");
    let mut spec = std::fs::read_to_string(&config).unwrap();
    spec = spec.replacen("\"terminal\": true", "\"terminal\": false", 1);
    let args_at = spec.find("\"args\": [").unwrap();
    let args_end = args_at + spec[args_at..].find(']').unwrap() + 1;
    let quoted = format!("{IN_CONTAINER:?}");
    spec.replace_range(args_at..args_end, &format!("\"args\": [\"/bin/sh\", \"-c\", {quoted}]"));
    let linux_at = spec.find("\"linux\": {").unwrap() + "\"linux\": {".len();
    spec.insert_str(
        linux_at,
        "\"seccomp\": {\"defaultAction\": \"SCMP_ACT_ALLOW\", \"architectures\": [\"SCMP_ARCH_AARCH64\"], \
         \"syscalls\": [{\"names\": [\"mkdirat\"], \"action\": \"SCMP_ACT_ERRNO\", \"errnoRet\": 1}]},",
    );
    std::fs::write(&config, spec).unwrap();
    let id = format!("fwe-test-{}", std::process::id());
    let out = crun(&["run", &id]);
    let want = "pid 1 host crun\n0::/\n1\nCapEff:\t0000000020000420\nNoNewPrivs:\t1\nSeccomp:\t2\n\
         Read-only file system\nOperation not permitted\n\
         core fd full mqueue null ptmx pts random shm stderr stdin stdout tty urandom zero\n\
         / /proc /dev /dev/pts /dev/shm /dev/mqueue /sys /sys/fs/cgroup /proc/keys /proc/sys\n3.20.10\n";
    if stdout(&out) != want {
        print_last_calls(&run_trace);
    }
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(stdout(&out), want);
    assert_eq!(out.status.code(), Some(0));
}

/// The standard `alpine` image as an OCI archive at `out`, made from its
/// one layer, the minirootfs, as the official image is: named
/// `docker.io/library/alpine:3.20`. With `docker`, it also has the
/// `manifest.json` that `docker save` writes beside the OCI layout.
fn alpine_oci_archive(manifest_name: &str, out: &Path, docker: bool) {
    let dir = out.with_extension("layout");
    let _ = std::fs::remove_dir_all(&dir);
    let blobs = dir.join("blobs/sha256");
    std::fs::create_dir_all(&blobs).unwrap();
    let blob = |bytes: &[u8]| {
        let tmp = dir.join("blob");
        std::fs::write(&tmp, bytes).unwrap();
        let digest = sha256(&tmp);
        std::fs::rename(&tmp, blobs.join(&digest)).unwrap();
        (digest, bytes.len())
    };
    let layer = std::fs::read(alpine_image(manifest_name)).unwrap();
    let tar = Command::new("gunzip").arg("-c").arg(alpine_image(manifest_name)).output().unwrap();
    let unpacked = dir.join("layer.tar");
    std::fs::write(&unpacked, &tar.stdout).unwrap();
    let diff_id = sha256(&unpacked);
    std::fs::remove_file(&unpacked).unwrap();
    let (layer_digest, layer_size) = blob(&layer);
    let config = format!(
        r#"{{"architecture":"arm64","variant":"v8","os":"linux","config":{{"Env":["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],"Cmd":["/bin/sh"]}},"rootfs":{{"type":"layers","diff_ids":["sha256:{diff_id}"]}}}}"#
    );
    let (config_digest, config_size) = blob(config.as_bytes());
    let manifest = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:{config_digest}","size":{config_size}}},"layers":[{{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"sha256:{layer_digest}","size":{layer_size}}}]}}"#
    );
    let (manifest_digest, manifest_size) = blob(manifest.as_bytes());
    std::fs::write(
        dir.join("index.json"),
        format!(
            r#"{{"schemaVersion":2,"manifests":[{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:{manifest_digest}","size":{manifest_size},"annotations":{{"org.opencontainers.image.ref.name":"docker.io/library/alpine:3.20"}}}}]}}"#
        ),
    )
    .unwrap();
    std::fs::write(dir.join("oci-layout"), r#"{"imageLayoutVersion":"1.0.0"}"#).unwrap();
    let mut entries = vec!["oci-layout", "index.json", "blobs"];
    if docker {
        std::fs::write(
            dir.join("manifest.json"),
            format!(
                r#"[{{"Config":"blobs/sha256/{config_digest}","RepoTags":["alpine:3.20"],"Layers":["blobs/sha256/{layer_digest}"]}}]"#
            ),
        )
        .unwrap();
        entries.push("manifest.json");
    }
    // Without the host's own attributes, which an archive made on Linux
    // would not have.
    run_checked(
        Command::new("tar")
            .args(["--no-xattrs", "--no-mac-metadata", "-cf"])
            .arg(out)
            .args(&entries)
            .current_dir(&dir),
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Print the last calls of each process in the `--strace-file` trace
/// `trace`, for a run that failed.
fn print_last_calls(trace: &Path) {
    let text = std::fs::read_to_string(trace).unwrap_or_default();
    let mut pids: Vec<&str> = Vec::new();
    for l in text.lines() {
        let p = l.split(']').next().unwrap_or("");
        if !pids.contains(&p) {
            pids.push(p);
        }
    }
    for p in pids {
        let lines: Vec<&str> = text.lines().filter(|l| l.starts_with(p)).collect();
        eprintln!("--- {p}] last calls:");
        for l in &lines[lines.len().saturating_sub(15)..] {
            eprintln!("{l}");
        }
    }
}

/// What the container prints in [`alpine_podman_runs_an_image`].
const IN_PODMAN: &str = "cat /etc/alpine-release; echo pid $$; id -u; \
    grep -E 'NoNewPrivs|Seccomp:' /proc/self/status; ls /proc | grep -E '^[0-9]+$' | head -1; \
    touch /made-here && echo writable; \
    awk '$5 == \"/\" && / - overlay / {print \"root on overlay\"}' /proc/self/mountinfo; exit 3";

/// Alpine's podman (fetched: `guests/alpine/fetch/podman.txt`), as root
/// with its default storage driver, `overlay`: it loads the standard
/// `alpine` image from an OCI archive and runs a container of it, whose
/// root is an overlay of the image's layer, through conmon and crun
/// (conmon adopting the container's init as a subreaper, and attaching to
/// it over a `SOCK_SEQPACKET` socket); the container's exit status is
/// podman's, and `--rm` leaves no container behind.
#[test]
fn alpine_podman_runs_an_image() {
    let root = std::env::temp_dir().join(format!("fwe-podman-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    run_checked(Command::new("cp").arg("-cR").arg(alpine_root("podman")).arg(&root));
    let etc = root.join("etc/containers");
    std::fs::write(
        etc.join("storage.conf"),
        "[storage]\ndriver = \"overlay\"\nrunroot = \"/run/containers/storage\"\n\
         graphroot = \"/var/lib/containers/storage\"\n",
    )
    .unwrap();
    std::fs::write(
        etc.join("containers.conf"),
        "[engine]\ncgroup_manager = \"cgroupfs\"\nevents_logger = \"file\"\n",
    )
    .unwrap();
    std::fs::create_dir_all(root.join("root")).unwrap();
    alpine_oci_archive("podman", &root.join("tmp/alpine.tar"), false);
    let _workload = workload();
    let podman = |args: &[&str]| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_fwe"));
        // As a login would have it, not the host's.
        cmd.env_clear().env("HOME", "/root").env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
        // Each process's calls, for a step that fails.
        let trace = root.join("tmp/podman.trace");
        let _ = std::fs::remove_file(&trace);
        cmd.arg("--strace").arg(format!("--strace-file={}", trace.display()));
        cmd.arg("--root").arg(&root).arg(root.join("usr/bin/podman")).args(args);
        let out = run_bounded_for(cmd, &[], Duration::from_secs(300));
        eprintln!(
            "--- podman {args:?} ({}) stderr:\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        // A `run` ends with its container's status; one killed hung.
        if !out.status.success() && (args[0] != "run" || out.status.code().is_none()) {
            print_last_calls(&trace);
        }
        out
    };
    let loaded = podman(&["load", "-i", "/tmp/alpine.tar"]);
    let images = podman(&["images", "--format", "{{.Repository}}:{{.Tag}}"]);
    let driver = podman(&["info", "--format", "{{.Store.GraphDriverName}}"]);
    let run = podman(&["run", "--rm", "--network=none", "alpine:3.20", "sh", "-c", IN_PODMAN]);
    let after = podman(&["ps", "-a", "--format", "{{.ID}}"]);
    let _ = std::fs::remove_dir_all(&root);
    assert!(stdout(&loaded).contains("Loaded image: docker.io/library/alpine:3.20"));
    assert_eq!(stdout(&images), "docker.io/library/alpine:3.20\n");
    assert_eq!(stdout(&driver), "overlay\n");
    assert_eq!(
        stdout(&run),
        "3.20.10\npid 1\n0\nNoNewPrivs:\t0\nSeccomp:\t2\n1\nwritable\nroot on overlay\n"
    );
    assert_eq!(run.status.code(), Some(3));
    assert_eq!(stdout(&after), "");
}

/// What the container prints in [`alpine_containerd_runs_an_image`].
const IN_CONTAINERD: &str = "cat /etc/alpine-release; echo pid $$; id -u; \
    grep -E 'NoNewPrivs|Seccomp:' /proc/self/status; touch /made-here && echo writable; \
    awk '$5 == \"/\" && / - overlay / {print \"root on overlay\"}' /proc/self/mountinfo; exit 4";

/// Alpine's containerd (fetched: `guests/alpine/fetch/containerd.txt`), as
/// root: the daemon runs, `ctr` imports the standard `alpine` image from an
/// OCI archive into its overlay snapshotter and runs a container of it
/// through containerd's runc shim and runc, in its own namespaces, with
/// `no_new_privs` and, asked for, containerd's default seccomp profile; the
/// container's exit status is `ctr`'s, and `--rm` leaves no container
/// behind.
#[test]
fn alpine_containerd_runs_an_image() {
    let root = std::env::temp_dir().join(format!("fwe-containerd-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    run_checked(Command::new("cp").arg("-cR").arg(alpine_root("containerd")).arg(&root));
    std::fs::create_dir_all(root.join("etc/containerd")).unwrap();
    std::fs::write(
        root.join("etc/containerd/config.toml"),
        "version = 2\nroot = \"/var/lib/containerd\"\nstate = \"/run/containerd\"\n\
         disabled_plugins = [\"io.containerd.grpc.v1.cri\"]\n\
         [grpc]\n  address = \"/run/containerd/containerd.sock\"\n",
    )
    .unwrap();
    alpine_oci_archive("containerd", &root.join("tmp/alpine.tar"), false);
    let _workload = workload();
    // Each process's calls, for a step that fails: the daemon's (its
    // shims' and runc's with them), and each ctr's.
    let fwe = |prog: &str, trace: &str| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_fwe"));
        cmd.env_clear().env("HOME", "/root").env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
        let trace = root.join("tmp").join(trace);
        let _ = std::fs::remove_file(&trace);
        cmd.arg("--strace").arg(format!("--strace-file={}", trace.display()));
        cmd.arg("--root").arg(&root).arg(root.join(prog));
        cmd
    };
    let log = std::fs::File::create(root.join("tmp/containerd.log")).unwrap();
    let mut daemon = fwe("usr/bin/containerd", "containerd.trace")
        .stdin(Stdio::null())
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .unwrap();
    let socket = root.join("run/containerd/containerd.sock");
    for _ in 0..600 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // `ctr` with `args`, which is to end with status `expect`; otherwise
    // the last calls of it and of containerd's processes (the shims, runc)
    // are printed.
    let ctr = |args: &[&str], expect: i32| {
        let trace = format!("ctr-{}.trace", args[..2].join("-"));
        let mut cmd = fwe("usr/bin/ctr", &trace);
        cmd.args(args);
        let out = run_bounded_for(cmd, &[], Duration::from_secs(120));
        eprintln!("--- ctr {args:?} stderr:\n{}", String::from_utf8_lossy(&out.stderr));
        if out.status.code() != Some(expect) {
            print_last_calls(&root.join("tmp").join(&trace));
            print_last_calls(&root.join("tmp/containerd.trace"));
        }
        out
    };
    let imported = ctr(&["images", "import", "/tmp/alpine.tar"], 0);
    let images = ctr(&["images", "ls", "-q"], 0);
    let run =
        ctr(&["run", "--rm", "docker.io/library/alpine:3.20", "t1", "sh", "-c", IN_CONTAINERD], 4);
    // Again with containerd's default seccomp profile.
    let filtered = ctr(
        &[
            "run",
            "--rm",
            "--seccomp",
            "docker.io/library/alpine:3.20",
            "t2",
            "sh",
            "-c",
            "grep Seccomp: /proc/self/status; uname -r",
        ],
        0,
    );
    let after = ctr(&["containers", "ls", "-q"], 0);
    // SAFETY: plain call, to the daemon this test started.
    unsafe { libc::kill(daemon.id() as i32, libc::SIGTERM) };
    let _ = daemon.wait();
    eprintln!(
        "--- containerd log:\n{}",
        std::fs::read_to_string(root.join("tmp/containerd.log")).unwrap_or_default()
    );
    let _ = std::fs::remove_dir_all(&root);
    assert!(stdout(&imported).contains("docker.io/library/alpine:3.20"), "{}", stdout(&imported));
    assert_eq!(stdout(&images), "docker.io/library/alpine:3.20\n");
    // ctr's spec sets no_new_privs and, without `--seccomp`, no filter.
    assert_eq!(
        stdout(&run),
        "3.20.10\npid 1\n0\nNoNewPrivs:\t1\nSeccomp:\t0\nwritable\nroot on overlay\n"
    );
    assert_eq!(run.status.code(), Some(4));
    assert!(stdout(&filtered).starts_with("Seccomp:\t2\n"), "{}", stdout(&filtered));
    assert_eq!(filtered.status.code(), Some(0));
    assert_eq!(stdout(&after), "");
}

/// What the container prints in [`alpine_docker_runs_and_builds_images`].
const IN_DOCKER: &str = "cat /etc/alpine-release; echo pid $$; id -u; \
    grep -E 'NoNewPrivs|Seccomp:' /proc/self/status; hostname | grep -cE '^[0-9a-f]{12}$'; \
    touch /made-here && echo writable; \
    awk '$5 == \"/\" && / - overlay / {print \"root on overlay\"}' /proc/self/mountinfo; exit 5";

/// The Dockerfile [`alpine_docker_runs_and_builds_images`] builds.
const DOCKERFILE: &str = "FROM alpine:3.20\n\
    RUN echo built > /built && mkdir /data\n\
    COPY greeting.txt /data/\n\
    CMD [\"sh\", \"-c\", \"cat /built /data/greeting.txt\"]\n";

/// The Compose project [`alpine_docker_runs_and_builds_images`] brings up:
/// a service that writes to a named volume, and one built from the
/// Dockerfile (with no network: the daemon has no bridge) that reads it
/// once the first has completed.
const COMPOSE: &str = "services:\n\
    \x20 store:\n\
    \x20   image: alpine:3.20\n\
    \x20   network_mode: none\n\
    \x20   volumes: [\"shared:/data\"]\n\
    \x20   command: [\"sh\", \"-c\", \"echo stored > /data/f\"]\n\
    \x20 reader:\n\
    \x20   build:\n\
    \x20     context: /tmp/context\n\
    \x20     network: none\n\
    \x20   network_mode: none\n\
    \x20   volumes: [\"shared:/data\"]\n\
    \x20   depends_on:\n\
    \x20     store:\n\
    \x20       condition: service_completed_successfully\n\
    \x20   command: [\"sh\", \"-c\", \"cat /data/f /built; exit 6\"]\n\
    volumes:\n\
    \x20 shared: {}\n";

/// Alpine's Docker Engine (fetched: `guests/alpine/fetch/docker.txt`), as
/// root, only where `FWE_DOCKER_TESTS` is set (CI's `docker` job): `dockerd`
/// starts its own containerd, with its `overlay2` storage, no bridge and no
/// iptables; the `docker` CLI loads the standard `alpine` image from an
/// archive, runs containers of it through containerd's runc shim and runc,
/// with no network and with the host's, and builds an image from a
/// Dockerfile with BuildKit (through the buildx plugin), whose `RUN` step
/// runs in a container and whose `COPY` takes a file of the build context;
/// a container of the built image runs. Docker Compose (the CLI's plugin)
/// brings up a project of two services sharing a named volume, one built,
/// the second started once the first completed, each with its own exit
/// status, and takes it down with its volume. Each container's
/// exit status is `docker`'s, and nothing is left behind.
#[test]
fn alpine_docker_runs_and_builds_images() {
    if !fetched_program_tests("FWE_DOCKER_TESTS") {
        return;
    }
    let root = std::env::temp_dir().join(format!("fwe-docker-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    run_checked(Command::new("cp").arg("-cR").arg(alpine_root("docker")).arg(&root));
    alpine_oci_archive("docker", &root.join("tmp/alpine.tar"), true);
    let context = root.join("tmp/context");
    std::fs::create_dir_all(&context).unwrap();
    std::fs::write(context.join("Dockerfile"), DOCKERFILE).unwrap();
    std::fs::write(context.join("greeting.txt"), "from the context\n").unwrap();
    std::fs::create_dir_all(root.join("tmp/compose")).unwrap();
    std::fs::write(root.join("tmp/compose/compose.yaml"), COMPOSE).unwrap();
    std::fs::create_dir_all(root.join("root")).unwrap();
    let _workload = workload();
    // Each process's calls, for a step that fails: the daemon's (containerd's,
    // the shims' and runc's with them), and each docker's.
    let fwe = |prog: &str, trace: &str| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_fwe"));
        cmd.env_clear().env("HOME", "/root").env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
        let trace = root.join("tmp").join(trace);
        let _ = std::fs::remove_file(&trace);
        cmd.arg("--strace").arg(format!("--strace-file={}", trace.display()));
        cmd.arg("--root").arg(&root).arg(root.join(prog));
        cmd
    };
    let log = std::fs::File::create(root.join("tmp/dockerd.log")).unwrap();
    let mut daemon = fwe("usr/bin/dockerd", "dockerd.trace")
        .args(["--debug", "--bridge=none", "--iptables=false", "--ip6tables=false"])
        .args(["--storage-driver=overlay2"])
        .stdin(Stdio::null())
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .unwrap();
    let socket = root.join("run/docker.sock");
    for _ in 0..1200 {
        if socket.exists() || daemon.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let dockerd_log = || std::fs::read_to_string(root.join("tmp/dockerd.log")).unwrap_or_default();
    // `docker` with `args`, which is to end with status `expect`; otherwise
    // the last calls of it and of the daemon's processes are printed.
    let step = std::cell::Cell::new(0);
    let docker = |args: &[&str], expect: i32| {
        step.set(step.get() + 1);
        let trace = format!("docker-{}-{}.trace", step.get(), args[0]);
        let mut cmd = fwe("usr/bin/docker", &trace);
        cmd.args(args);
        let out = run_bounded_for(cmd, &[], Duration::from_secs(300));
        eprintln!(
            "--- docker {args:?} ({}) stderr:\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        if out.status.code() != Some(expect) {
            print_last_calls(&root.join("tmp").join(&trace));
            print_last_calls(&root.join("tmp/dockerd.trace"));
            eprintln!("--- dockerd log:\n{}", dockerd_log());
        }
        out
    };
    let info = docker(&["info", "--format", "{{.Driver}} {{.CgroupVersion}} {{.Name}}"], 0);
    let loaded = docker(&["load", "-i", "/tmp/alpine.tar"], 0);
    let images = docker(&["images", "--format", "{{.Repository}}:{{.Tag}}"], 0);
    let run = docker(&["run", "--rm", "--network=none", "alpine:3.20", "sh", "-c", IN_DOCKER], 5);
    let host = docker(&["run", "--rm", "--network=host", "alpine:3.20", "hostname"], 0);
    let built = docker(&["build", "--network=none", "-t", "fwe-built:1", "/tmp/context"], 0);
    let ran = docker(&["run", "--rm", "--network=none", "fwe-built:1"], 0);
    let compose = ["compose", "-p", "fwe", "-f", "/tmp/compose/compose.yaml"];
    let up = docker(&[&compose[..], &["up", "--no-color"]].concat(), 0);
    let codes = docker(
        &[&compose[..], &["ps", "-a", "--format", "{{.Service}} {{.ExitCode}}"]].concat(),
        0,
    );
    let down = docker(&[&compose[..], &["down", "--volumes"]].concat(), 0);
    let after = docker(&["ps", "-a", "--format", "{{.ID}}"], 0);
    let volumes = docker(&["volume", "ls", "-q"], 0);
    // SAFETY: plain call, to the daemon this test started.
    unsafe { libc::kill(daemon.id() as i32, libc::SIGTERM) };
    let mut ended = None;
    for _ in 0..600 {
        ended = daemon.try_wait().unwrap();
        if ended.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if ended.is_none() {
        let _ = daemon.kill();
        let _ = daemon.wait();
    }
    eprintln!("--- dockerd log:\n{}", dockerd_log());
    // The traces and the daemon's log, for CI to keep should a step fail.
    let kept = Path::new(env!("CARGO_TARGET_TMPDIR")).join("docker-traces");
    let _ = std::fs::remove_dir_all(&kept);
    std::fs::create_dir_all(&kept).unwrap();
    for e in std::fs::read_dir(root.join("tmp")).unwrap().flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        if name.ends_with(".trace") || name.ends_with(".log") {
            let _ = std::fs::copy(e.path(), kept.join(&*name));
        }
    }
    let _ = std::fs::remove_dir_all(&root);
    let info = stdout(&info);
    let name = info.split_whitespace().nth(2).unwrap_or_default().to_string();
    assert!(info.starts_with("overlay2 2 "), "{info}");
    assert!(stdout(&loaded).contains("Loaded image: alpine:3.20"), "{}", stdout(&loaded));
    assert_eq!(stdout(&images), "alpine:3.20\n");
    // Docker's default seccomp profile, and no `no_new_privs`.
    assert_eq!(
        stdout(&run),
        "3.20.10\npid 1\n0\nNoNewPrivs:\t0\nSeccomp:\t2\n1\nwritable\nroot on overlay\n"
    );
    assert_eq!(run.status.code(), Some(5));
    // The host's network, and with it its name.
    assert_eq!(stdout(&host), format!("{name}\n"));
    assert_eq!(built.status.code(), Some(0));
    assert_eq!(stdout(&ran), "built\nfrom the context\n");
    let up = stdout(&up);
    assert!(up.contains("reader-1  | stored\n") && up.contains("reader-1  | built\n"), "{up}");
    let mut codes: Vec<String> = stdout(&codes).lines().map(str::to_string).collect();
    codes.sort();
    assert_eq!(codes, ["reader 6", "store 0"]);
    assert_eq!(down.status.code(), Some(0));
    assert_eq!(stdout(&after), "");
    assert_eq!(stdout(&volumes), "");
    assert!(ended.is_some_and(|s| s.success()), "dockerd did not end cleanly: {ended:?}");
}

/// The Containerfile [`alpine_podman_builds_pulls_and_runs_rootless`]
/// builds.
const CONTAINERFILE: &str = "FROM docker.io/library/alpine:3.20\n\
    RUN echo built > /built && mkdir /data\n\
    COPY greeting.txt /data/\n\
    CMD [\"sh\", \"-c\", \"cat /built /data/greeting.txt\"]\n";

/// What a rootless container prints: its uid, its user namespace's map (its
/// root the user, the rest the user's subordinate ids), and a file a
/// subordinate id owns.
const IN_ROOTLESS: &str = "id -u; awk '{print $1, $2, $3}' /proc/self/uid_map; \
    touch /f && chown 1234 /f && stat -c %u /f";

/// Alpine's podman (fetched: `guests/alpine/fetch/podman-further.txt`),
/// only where `FWE_PODMAN_TESTS` is set (CI's `podman` job): as root, it
/// builds an image from a Containerfile (Buildah's `RUN` in a container
/// and `COPY` from the context) and runs it, pushes it to a registry
/// (distribution's, running alongside) and pulls it back; then as an
/// ordinary user, rootless, in a user namespace `newuidmap` maps from
/// `/etc/subuid` (which it may, by its file capability `cap_setuid`), with
/// overlay storage in the user's home, it pulls the image from the registry
/// and runs it, and runs a container whose root is the user.
#[test]
fn alpine_podman_builds_pulls_and_runs_rootless() {
    if !fetched_program_tests("FWE_PODMAN_TESTS") {
        return;
    }
    let root = std::env::temp_dir().join(format!("fwe-podman2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    run_checked(Command::new("cp").arg("-cR").arg(alpine_root("podman-further")).arg(&root));
    let etc = root.join("etc/containers");
    std::fs::write(
        etc.join("storage.conf"),
        "[storage]\ndriver = \"overlay\"\nrunroot = \"/run/containers/storage\"\n\
         graphroot = \"/var/lib/containers/storage\"\n",
    )
    .unwrap();
    std::fs::write(
        etc.join("containers.conf"),
        "[engine]\ncgroup_manager = \"cgroupfs\"\nevents_logger = \"file\"\n",
    )
    .unwrap();
    std::fs::write(
        etc.join("registries.conf"),
        "unqualified-search-registries = []\n\
         [[registry]]\nlocation = \"127.0.0.1:15000\"\ninsecure = true\n",
    )
    .unwrap();
    std::fs::write(
        root.join("etc/docker-registry/config.yml"),
        "version: 0.1\nstorage:\n  filesystem:\n    rootdirectory: /var/lib/registry\n\
         http:\n  addr: 127.0.0.1:15000\n",
    )
    .unwrap();
    // The user, its subordinate ids, its home and its runtime directory
    // (made its own below, as root).
    let mut passwd = std::fs::read_to_string(root.join("etc/passwd")).unwrap();
    passwd.push_str("user:x:1000:1000:user:/home/user:/bin/sh\n");
    std::fs::write(root.join("etc/passwd"), passwd).unwrap();
    let mut group = std::fs::read_to_string(root.join("etc/group")).unwrap();
    group.push_str("user:x:1000:\n");
    std::fs::write(root.join("etc/group"), group).unwrap();
    std::fs::write(root.join("etc/subuid"), "user:100000:65536\n").unwrap();
    std::fs::write(root.join("etc/subgid"), "user:100000:65536\n").unwrap();
    for d in ["root", "home/user", "run/user/1000", "tmp/context"] {
        std::fs::create_dir_all(root.join(d)).unwrap();
    }
    std::fs::write(root.join("tmp/context/Containerfile"), CONTAINERFILE).unwrap();
    std::fs::write(root.join("tmp/context/greeting.txt"), "from the context\n").unwrap();
    alpine_oci_archive("podman-further", &root.join("tmp/alpine.tar"), false);
    let _workload = workload();
    // Each process's calls, for a step that fails.
    let fwe = |args: &[&str], trace: &str| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_fwe"));
        cmd.env_clear().env("HOME", "/root").env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
        let trace = root.join("tmp").join(trace);
        let _ = std::fs::remove_file(&trace);
        cmd.arg("--strace").arg(format!("--strace-file={}", trace.display()));
        cmd.arg("--root").arg(&root).arg(root.join(args[0].trim_start_matches('/')));
        cmd.args(&args[1..]);
        cmd
    };
    let log = std::fs::File::create(root.join("tmp/registry.log")).unwrap();
    let mut registry = fwe(
        &["/usr/bin/docker-registry", "serve", "/etc/docker-registry/config.yml"],
        "registry.trace",
    )
    .stdin(Stdio::null())
    .stdout(log.try_clone().unwrap())
    .stderr(log)
    .spawn()
    .unwrap();
    let registry_log =
        || std::fs::read_to_string(root.join("tmp/registry.log")).unwrap_or_default();
    // A shell command, as root or (`user`) as the user, which is to end
    // with status `expect`; otherwise its processes' last calls and the
    // registry's log are printed.
    let step = std::cell::Cell::new(0);
    let sh = |script: &str, user: bool, expect: i32| {
        step.set(step.get() + 1);
        let trace = format!("step-{}.trace", step.get());
        // BusyBox's applets, by name: `/bin/sh` and `/bin/su` are links to
        // it, which name it by its path in the root.
        let cmd = if user {
            fwe(&["/bin/busybox", "su", "-s", "/bin/sh", "user", "-c", script], &trace)
        } else {
            fwe(&["/bin/busybox", "sh", "-c", script], &trace)
        };
        let out = run_bounded_for(cmd, &[], Duration::from_secs(300));
        eprintln!(
            "--- {script:?} ({}) stderr:\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        if out.status.code() != Some(expect) {
            print_last_calls(&root.join("tmp").join(&trace));
            eprintln!("--- registry log:\n{}", registry_log());
        }
        out
    };
    let image = "127.0.0.1:15000/fwe/built:1";
    sh("chown -R user:user /home/user /run/user/1000 && chmod 700 /run/user/1000", false, 0);
    let loaded = sh("podman load -q -i /tmp/alpine.tar", false, 0);
    let built = sh(
        &format!("podman build -q --network=none -t {image} /tmp/context >/dev/null && echo built"),
        false,
        0,
    );
    let ran = sh(&format!("podman run --rm --network=none {image}"), false, 0);
    let pushed = sh(
        &format!("podman push -q {image} && podman rmi -f {image} >/dev/null && echo pushed"),
        false,
        0,
    );
    let pulled = sh(
        &format!("podman pull -q {image} >/dev/null && podman run --rm --network=none {image}"),
        false,
        0,
    );
    // Rootless, as the user.
    let rootless_env = "export XDG_RUNTIME_DIR=/run/user/1000 HOME=/home/user;";
    let info = sh(
        &format!(
            "{rootless_env} podman info --format '{{{{.Host.Security.Rootless}}}} {{{{.Store.GraphDriverName}}}}'"
        ),
        true,
        0,
    );
    let user_pulled = sh(
        &format!(
            "{rootless_env} podman pull -q {image} >/dev/null && podman run --rm --network=none {image}"
        ),
        true,
        0,
    );
    let mapped = sh(
        &format!(
            "{rootless_env} podman load -q -i /tmp/alpine.tar >/dev/null && \
             podman run --rm --network=none docker.io/library/alpine:3.20 sh -c {}",
            shell_quote(IN_ROOTLESS)
        ),
        true,
        0,
    );
    // SAFETY: plain call, to the registry this test started.
    unsafe { libc::kill(registry.id() as i32, libc::SIGTERM) };
    let _ = registry.wait();
    // The traces and logs, for CI to keep should a step fail.
    let kept = Path::new(env!("CARGO_TARGET_TMPDIR")).join("podman-traces");
    let _ = std::fs::remove_dir_all(&kept);
    std::fs::create_dir_all(&kept).unwrap();
    for e in std::fs::read_dir(root.join("tmp")).unwrap().flatten() {
        let name = e.file_name();
        let name = name.to_string_lossy();
        if name.ends_with(".trace") || name.ends_with(".log") {
            let _ = std::fs::copy(e.path(), kept.join(&*name));
        }
    }
    let _ = std::fs::remove_dir_all(&root);
    assert!(stdout(&loaded).contains("alpine:3.20"), "{}", stdout(&loaded));
    assert_eq!(stdout(&built), "built\n");
    assert_eq!(stdout(&ran), "built\nfrom the context\n");
    assert_eq!(stdout(&pushed), "pushed\n");
    assert_eq!(stdout(&pulled), "built\nfrom the context\n");
    assert_eq!(stdout(&info), "true overlay\n");
    assert_eq!(stdout(&user_pulled), "built\nfrom the context\n");
    assert_eq!(stdout(&mapped), "0\n0 1000 1\n1 100000 65536\n1234\n");
}

/// `s` quoted for a POSIX shell, as one word.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Debian's podman 4.3 (fetched: `guests/debian/fetch/podman.txt`), a
/// non-PIE executable the VM runs, only where `FWE_PODMAN_TESTS` is set
/// (CI's `podman` job), as root: it loads the standard `alpine` image and
/// runs a container of it through conmon and crun, which run natively, each
/// a program podman's VM process starts with `execve`; the container's
/// exit status is podman's.
#[test]
fn debian_podman_runs_in_the_vm() {
    if !fetched_program_tests("FWE_PODMAN_TESTS") {
        return;
    }
    let Some(_) = hv_mode() else {
        eprintln!("skipped: no hypervisor on this host");
        return;
    };
    let cached = fetched_root("podman");
    let root = std::env::temp_dir().join(format!("fwe-debpodman-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    run_checked(Command::new("cp").arg("-cR").arg(&cached).arg(&root));
    let etc = root.join("etc/containers");
    std::fs::create_dir_all(&etc).unwrap();
    std::fs::write(
        etc.join("storage.conf"),
        "[storage]\ndriver = \"overlay\"\nrunroot = \"/run/containers/storage\"\n\
         graphroot = \"/var/lib/containers/storage\"\n",
    )
    .unwrap();
    std::fs::write(
        etc.join("containers.conf"),
        "[engine]\ncgroup_manager = \"cgroupfs\"\nevents_logger = \"file\"\n\
         runtime = \"crun\"\n",
    )
    .unwrap();
    std::fs::write(root.join("etc/passwd"), "root:x:0:0:root:/root:/bin/sh\n").unwrap();
    std::fs::write(root.join("etc/group"), "root:x:0:\n").unwrap();
    for d in ["root", "tmp", "run", "var/tmp"] {
        std::fs::create_dir_all(root.join(d)).unwrap();
    }
    alpine_oci_archive("podman", &root.join("tmp/alpine.tar"), false);
    let _workload = workload();
    let podman = |args: &[&str]| {
        let mut cmd = hv_command().unwrap();
        let trace = root.join("tmp/podman.trace");
        let _ = std::fs::remove_file(&trace);
        cmd.arg("--strace").arg(format!("--strace-file={}", trace.display()));
        cmd.arg("--root").arg(&root).arg(root.join("usr/bin/podman")).args(args);
        cmd.env_clear().env("HOME", "/root").env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
        cmd.stdin(Stdio::null());
        let out = run_hv_for(cmd, "podman", Duration::from_secs(1200));
        eprintln!(
            "--- podman {args:?} ({}) stderr:\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        if !out.status.success() && args[0] != "run" {
            print_last_calls(&trace);
        }
        out
    };
    let loaded = podman(&["--log-level=debug", "load", "-i", "/tmp/alpine.tar"]);
    if !stdout(&loaded).contains("Loaded image") {
        print_last_calls(&root.join("tmp/podman.trace"));
        // fwe's notes of kill relays and mailboxes, from every process.
        let whole = std::fs::read_to_string(root.join("tmp/podman.trace")).unwrap_or_default();
        for l in whole.lines().filter(|l| l.contains("kill rel") || l.contains("mailbox")) {
            eprintln!("{l}");
        }
        // The whole trace, for CI to keep.
        let kept = Path::new(env!("CARGO_TARGET_TMPDIR")).join("podman-traces");
        let _ = std::fs::create_dir_all(&kept);
        let _ = std::fs::copy(root.join("tmp/podman.trace"), kept.join("debian-load.trace"));
    }
    // The name it was loaded as (`Loaded image(s): <name>`).
    let name = stdout(&loaded)
        .lines()
        .find_map(|l| l.strip_prefix("Loaded image").and_then(|l| l.split_once(": ")))
        .map(|(_, n)| n.trim().to_string())
        .unwrap_or_default();
    eprintln!("--- loaded: {}", stdout(&loaded));
    let images = podman(&["images", "--format", "{{.Repository}}:{{.Tag}} {{.ID}}"]);
    eprintln!("--- images: {}", stdout(&images));
    let run = podman(&[
        "run",
        "--rm",
        "--network=none",
        &name,
        "sh",
        "-c",
        "cat /etc/alpine-release; echo pid $$; id -u; exit 3",
    ]);
    if run.status.code() != Some(3) {
        print_last_calls(&root.join("tmp/podman.trace"));
    }
    let _ = std::fs::remove_dir_all(&root);
    assert!(stdout(&loaded).contains("alpine:3.20"), "{}", stdout(&loaded));
    assert_eq!(stdout(&run), "3.20.10\npid 1\n0\n");
    assert_eq!(run.status.code(), Some(3));
}

/// Debian's Node.js 18 (fetched: `guests/debian/fetch/node.txt`): V8's
/// JIT on a hot function, ICU, OpenSSL's digests (its assembly keeps
/// constant tables among its code, which must not be rewritten), zlib, the
/// file system with promises and timers, a child process, an HTTP server
/// and client in one process, and a worker thread.
#[test]
fn debian_node_runs_a_workload() {
    let root = fetched_root("node");
    let _workload = workload();
    let script = format!("/tmp/fwe-node-{}.js", std::process::id());
    let data = format!("/tmp/fwe-node-{}.txt", std::process::id());
    std::fs::write(
        root.join(script.trim_start_matches('/')),
        format!(
            r#"
const crypto = require('crypto');
const zlib = require('zlib');
const fs = require('fs');
const http = require('http');
const {{ execFileSync }} = require('child_process');
const {{ Worker }} = require('worker_threads');

function fib(n) {{ return n < 2 ? n : fib(n - 1) + fib(n - 2); }}
let s = 0; for (let i = 0; i < 2000; i++) s += fib(15);
console.log('fib', fib(25), s);
console.log('intl', new Intl.NumberFormat('de-DE').format(1234567.891),
            new Date(0).toLocaleDateString('en-GB', {{ timeZone: 'UTC' }}));
for (const a of ['md5', 'sha1', 'sha256', 'sha512', 'ripemd160', 'sha3-256'])
  console.log(a, crypto.createHash(a).update('fun-with-emulators').digest('hex').slice(0, 16));
const big = Buffer.alloc(100000, 'abc');
console.log('zlib', zlib.gunzipSync(zlib.gzipSync(big)).equals(big));
fs.writeFileSync('{data}', 'line1\nline2\n');
console.log('fs', fs.readFileSync('{data}', 'utf8').split('\n').length);
console.log('child', execFileSync('/bin/bash', ['-c', 'echo $((6 * 7))']).toString().trim());
(async () => {{
  await new Promise(r => setTimeout(r, 20));
  console.log('promises', (await fs.promises.readFile('{data}', 'utf8')).length);
  fs.unlinkSync('{data}');
  const server = http.createServer((req, res) => res.end('hi ' + req.url));
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const body = await new Promise((resolve, reject) => {{
    http.get({{ host: '127.0.0.1', port: server.address().port, path: '/x' }}, res => {{
      let b = ''; res.on('data', d => b += d); res.on('end', () => resolve(b));
    }}).on('error', reject);
  }});
  console.log('http', body);
  server.close();
  const w = new Worker('require("worker_threads").parentPort.postMessage(21 * 2)', {{ eval: true }});
  w.on('message', m => console.log('worker', m));
  w.on('exit', c => console.log('worker exit', c));
}})();
"#
        ),
    )
    .unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fwe"));
    cmd.arg("--root")
        .arg(&root)
        .arg(root.join("usr/bin/node"))
        .arg(&script)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/tmp")
        .stdin(Stdio::null());
    let out = run_bounded_for(cmd, &[], Duration::from_secs(60));
    let _ = std::fs::remove_file(root.join(script.trim_start_matches('/')));
    eprintln!("--- node stderr:\n{}", String::from_utf8_lossy(&out.stderr));
    // The digests are the host's (`shasum`, `md5`, Python's hashlib).
    assert_eq!(
        stdout(&out),
        "fib 75025 1220000\n\
         intl 1.234.567,891 01/01/1970\n\
         md5 83cce8037da91bde\n\
         sha1 c650da2b9b797302\n\
         sha256 9c3ef3144c6828d9\n\
         sha512 fca8db3fbca619cd\n\
         ripemd160 74e7d081086e35cb\n\
         sha3-256 3bee16617c9f352e\n\
         zlib true\n\
         fs 3\n\
         child 42\n\
         promises 12\n\
         http hi /x\n\
         worker 42\n\
         worker exit 0\n"
    );
    assert_eq!(out.status.code(), Some(0));
}

/// Debian's Rust toolchain (fetched: `guests/debian/fetch/rust.txt`): Cargo
/// builds a two-crate project offline in release mode — rustc and its LLVM
/// compiling, GNU ld linking — and runs it, then builds and runs a crate's
/// unit tests. Debian's rustc links through `cc`, and Debian's GCC is a
/// non-PIE executable (only the hypervisor backend runs it), so the project
/// has rustc call ld itself with the C runtime's start files.
#[test]
fn debian_cargo_builds_and_tests_a_project() {
    let root = fetched_root("rust");
    let _workload = workload();
    let proj = format!("tmp/fwe-cargo-{}", std::process::id());
    let dir = root.join(&proj);
    let _ = std::fs::remove_dir_all(&dir);
    for d in ["src", "util/src", ".cargo"] {
        std::fs::create_dir_all(dir.join(d)).unwrap();
    }
    let files = [
        (
            "Cargo.toml",
            "[package]\nname = \"proj\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n\
             [dependencies]\nutil = { path = \"util\" }\n",
        ),
        (
            "util/Cargo.toml",
            "[package]\nname = \"util\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        ),
        (
            "util/src/lib.rs",
            "/// The primes below `n`, by a sieve.\n\
             pub fn primes(n: usize) -> Vec<usize> {\n\
             \x20   let mut sieve = vec![true; n];\n\
             \x20   (2..n).filter(|&i| {\n\
             \x20       if sieve[i] { (i * i..n).step_by(i).for_each(|j| sieve[j] = false); }\n\
             \x20       sieve[i]\n\
             \x20   }).collect()\n\
             }\n\n\
             #[cfg(test)]\n\
             mod tests {\n\
             \x20   #[test]\n\
             \x20   fn small_primes() { assert_eq!(super::primes(12), [2, 3, 5, 7, 11]); }\n\
             }\n",
        ),
        (
            "src/main.rs",
            "fn main() {\n\
             \x20   let p = util::primes(100_000);\n\
             \x20   let sums: Vec<_> = p.chunks(p.len() / 4 + 1).map(|c| c.to_vec())\n\
             \x20       .map(|c| std::thread::spawn(move || c.iter().sum::<usize>())).collect();\n\
             \x20   let sum: usize = sums.into_iter().map(|t| t.join().unwrap()).sum();\n\
             \x20   println!(\"{} primes below 100000, the last {}, summing to {sum}\", p.len(), p.last().unwrap());\n\
             }\n",
        ),
    ];
    for (name, text) in files {
        std::fs::write(dir.join(name), text).unwrap();
    }
    // rustc calls GNU ld directly, with what gcc would add around it.
    let (gcc, lib) = ("/usr/lib/gcc/aarch64-linux-gnu/12", "/usr/lib/aarch64-linux-gnu");
    let link = format!(
        "-dynamic-linker /lib/ld-linux-aarch64.so.1 {lib}/Scrt1.o {lib}/crti.o \
         {gcc}/crtbeginS.o -L{gcc} -L{lib} -lgcc_s -lc {gcc}/crtendS.o {lib}/crtn.o"
    );
    std::fs::write(
        dir.join(".cargo/config.toml"),
        format!(
            "[target.aarch64-unknown-linux-gnu]\n\
             linker = \"/usr/bin/aarch64-linux-gnu-ld.bfd\"\n\
             rustflags = [\"-C\", \"linker-flavor=ld\", \"-C\", \"link-args={link}\"]\n"
        ),
    )
    .unwrap();
    let script = format!(
        "set -e\ncd /{proj}\n\
         cargo build --release --offline -q\n\
         ./target/release/proj\n\
         cargo test --offline -q -p util 2>&1\n"
    );
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fwe"));
    cmd.arg("--root")
        .arg(&root)
        .arg(root.join("bin/bash"))
        .args(["-c", &script])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/tmp")
        .stdin(Stdio::null());
    // About 20 s alone: each rustc is a fresh fwe that prepares over 140 MB
    // of code (rustc's driver and LLVM) before LLVM compiles the crates.
    let out = run_bounded_for(cmd, &[], Duration::from_secs(120));
    let _ = std::fs::remove_dir_all(&dir);
    eprintln!("--- cargo stderr:\n{}", String::from_utf8_lossy(&out.stderr));
    let text = stdout(&out);
    assert!(
        text.starts_with("9592 primes below 100000, the last 99991, summing to 454396537\n"),
        "{text}"
    );
    assert!(text.contains("running 1 test\n.\n"), "{text}");
    assert!(text.contains("test result: ok. 1 passed; 0 failed"), "{text}");
    assert_eq!(out.status.code(), Some(0), "{text}");
}

/// Debian's apt (fetched: `guests/debian/fetch/apt.txt`) installs a package
/// from a local repository and removes it: `apt-get update` reads the
/// repository's index through its `file` method, `apt-get install` resolves
/// the package against the dpkg database and hands it to dpkg, which
/// unpacks and configures it (talking to apt through a pseudo-terminal);
/// the program then runs, and `apt-get remove` takes it away again. The
/// package, GNU hello, is fetched too (`fetch/apt-repo.txt`) and only
/// served from the repository.
#[test]
fn debian_apt_installs_and_removes_a_package() {
    // A copy of the cached root (an APFS clone, so cheap), as the test
    // changes it.
    let root = std::env::temp_dir().join(format!("fwe-apt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    run_checked(Command::new("cp").arg("-cR").arg(fetched_root("apt")).arg(&root));
    let _workload = workload();
    let dir = |d: &str| std::fs::create_dir_all(root.join(d)).unwrap();
    for d in [
        "repo",
        "root",
        "var/lib/dpkg/info",
        "var/lib/dpkg/updates",
        "var/lib/dpkg/triggers",
        "var/lib/apt/lists/partial",
        "var/cache/apt/archives/partial",
        "var/log/apt",
        "etc/apt/apt.conf.d",
        "etc/apt/preferences.d",
        "etc/apt/sources.list.d",
        "etc/dpkg/dpkg.cfg.d",
    ] {
        dir(d);
    }
    // The repository: the package and its index stanza, made from its own
    // control file as dpkg-scanpackages would.
    let deb = &fetched_debs("apt-repo")[0];
    let name = deb.file_name().unwrap().to_string_lossy().into_owned();
    std::fs::copy(deb, root.join("repo").join(&name)).unwrap();
    let control = Command::new("sh")
        .arg("-c")
        .arg("ar p \"$0\" control.tar.xz | tar xOf - ./control")
        .arg(deb)
        .output()
        .unwrap();
    assert!(control.status.success());
    let sha = Command::new("shasum").args(["-a", "256"]).arg(deb).output().unwrap();
    let sha = String::from_utf8_lossy(&sha.stdout).split_whitespace().next().unwrap().to_string();
    let size = std::fs::metadata(deb).unwrap().len();
    std::fs::write(
        root.join("repo/Packages"),
        format!(
            "{}Filename: ./{name}\nSize: {size}\nSHA256: {sha}\n",
            String::from_utf8_lossy(&control.stdout)
        ),
    )
    .unwrap();
    std::fs::write(root.join("etc/apt/sources.list"), "deb [trusted=yes] file:/repo ./\n").unwrap();
    // The dpkg database: glibc installed, as a bootstrapped system has it.
    std::fs::write(
        root.join("var/lib/dpkg/status"),
        "Package: libc6\nStatus: install ok installed\nPriority: optional\n\
         Maintainer: GNU Libc Maintainers <debian-glibc@lists.debian.org>\n\
         Architecture: arm64\nMulti-Arch: same\nVersion: 2.36-9+deb12u14\n\
         Description: GNU C Library: Shared libraries\n\n",
    )
    .unwrap();
    std::fs::write(root.join("var/lib/dpkg/available"), "").unwrap();
    std::fs::write(
        root.join("etc/passwd"),
        "root:x:0:0:root:/root:/bin/bash\n_apt:x:42:65534::/nonexistent:/usr/sbin/nologin\n",
    )
    .unwrap();
    std::fs::write(root.join("etc/group"), "root:x:0:\nnogroup:x:65534:\n").unwrap();

    let script = r#"
        set -e
        apt-get update -qq
        apt-get install -y -qq hello
        hello
        hello --greeting='hello from a package apt installed'
        dpkg-query -W -f='${Package} ${Version} ${Status}\n' hello
        apt-get remove -y -qq hello
        test ! -e /usr/bin/hello && echo removed
        dpkg-query -W hello 2>/dev/null || echo "no longer known to dpkg"
    "#;
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fwe"));
    cmd.arg("--root")
        .arg(&root)
        .arg(root.join("bin/bash"))
        .args(["-c", script])
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("HOME", "/root")
        .stdin(Stdio::null());
    let out = run_bounded_for(cmd, &[], Duration::from_secs(60));
    let _ = std::fs::remove_dir_all(&root);
    eprintln!("--- apt ({}) stderr:\n{}", out.status, String::from_utf8_lossy(&out.stderr));
    // dpkg's progress, which apt relays, is interleaved; the lines asked for
    // come in order.
    let text = stdout(&out);
    let mut lines = text.lines();
    for want in [
        "Hello, world!",
        "hello from a package apt installed",
        "hello 2.10-3 install ok installed",
        "Removing hello (2.10-3) ...",
        "removed",
        "no longer known to dpkg",
    ] {
        assert!(lines.any(|l| l.ends_with(want)), "{want:?} missing from:\n{text}");
    }
    assert_eq!(out.status.code(), Some(0));
}

/// A running guest server, stopped (`SIGTERM`) and reaped when dropped.
struct Server(std::process::Child);

impl Drop for Server {
    fn drop(&mut self) {
        // SAFETY: signalling the child this test started.
        unsafe { libc::kill(self.0.id() as i32, libc::SIGTERM) };
        let start = Instant::now();
        while self.0.try_wait().ok().flatten().is_none() {
            if start.elapsed() > Duration::from_secs(5) {
                let _ = self.0.kill();
                let _ = self.0.wait();
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// One HTTP/1.0 request to `127.0.0.1:port`: the status line and the body.
fn http(port: u16, method: &str, path: &str, body: &str) -> (String, Vec<u8>) {
    use std::io::{Read, Write};
    let fail = |what: &str, e: std::io::Error| -> ! { panic!("{method} {path}: {what}: {e}") };
    let mut s =
        std::net::TcpStream::connect(("127.0.0.1", port)).unwrap_or_else(|e| fail("connecting", e));
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let length =
        if body.is_empty() { String::new() } else { format!("Content-Length: {}\r\n", body.len()) };
    write!(s, "{method} {path} HTTP/1.0\r\nHost: localhost\r\n{length}\r\n{body}")
        .unwrap_or_else(|e| fail("sending", e));
    let mut reply = Vec::new();
    s.read_to_end(&mut reply).unwrap_or_else(|e| fail("reading the reply", e));
    let split = reply.windows(4).position(|w| w == b"\r\n\r\n").expect("no end of headers");
    let head = String::from_utf8_lossy(&reply[..split]).into_owned();
    let status = head.lines().next().unwrap_or("").to_string();
    (status, reply[split + 4..].to_vec())
}

/// Debian's lighttpd, M2's web server: it serves a page, a large file
/// (through `sendfile`), a directory listing from a loaded module and a
/// 404, to clients at once from one `epoll` loop; and through `mod_cgi`
/// runs a bash script per request (fork, exec and pipes) that keeps its
/// state in an SQLite database.
#[test]
fn debian_lighttpd_serves_files_and_cgi() {
    let _workload = workload();
    let root = ProgramRoot::new("lighttpd", &["etc", "usr/lib/lighttpd", "srv/www/sub"]);
    std::fs::copy(debian_bin("lighttpd"), root.path("bin/lighttpd")).unwrap();
    std::fs::copy(debian_bin("sqlite3"), root.path("bin/sqlite3")).unwrap();
    for module in ["mod_cgi.so", "mod_dirlisting.so"] {
        std::fs::copy(
            repo().join("guests/debian/lighttpd").join(module),
            root.path("usr/lib/lighttpd").join(module),
        )
        .unwrap();
    }
    std::fs::write(root.path("srv/www/index.html"), "hello from lighttpd\n").unwrap();
    let big: String = (1..=50_000).map(|i| format!("{i}\n")).collect();
    std::fs::write(root.path("srv/www/big.txt"), &big).unwrap();
    std::fs::write(root.path("srv/www/sub/a.txt"), "a\n").unwrap();
    std::fs::write(
        root.path("srv/www/count.sh"),
        r#"echo "Content-Type: text/plain"
echo
if [ "$REQUEST_METHOD" = POST ]; then
    read -r -n "$CONTENT_LENGTH" body
    sqlite3 /tmp/db "insert into hits(who) values ('$body')"
fi
echo "$REQUEST_METHOD $QUERY_STRING: $(sqlite3 /tmp/db 'select group_concat(who) from hits')"
"#,
    )
    .unwrap();
    let mut init = root.command("/bin/sqlite3");
    init.args(["/tmp/db", "create table hits(who text); insert into hits values ('init')"]);
    assert_eq!(run_bounded(init).status.code(), Some(0));

    // A port free a moment ago, which another test may take before lighttpd
    // binds it: then lighttpd ends, and another is tried.
    let log_path = root.path("tmp/error.log");
    let mut started = None;
    for _ in 0..5 {
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        std::fs::write(
            root.path("etc/lighttpd.conf"),
            format!(
                r#"server.document-root = "/srv/www"
server.bind = "127.0.0.1"
server.port = {port}
server.modules = ("mod_dirlisting", "mod_cgi")
server.upload-dirs = ("/tmp")
server.errorlog = "/tmp/error.log"
index-file.names = ("index.html")
dir-listing.activate = "enable"
cgi.assign = (".sh" => "/bin/bash")
mimetype.assign = (".html" => "text/html", ".txt" => "text/plain")
"#
            ),
        )
        .unwrap();
        let _ = std::fs::remove_file(&log_path);
        // Its failed calls on standard error, for a start that fails.
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_fwe"));
        cmd.arg("--strace=failures")
            .arg("--root")
            .arg(&root.0)
            .arg(root.path("bin/lighttpd"))
            .args(["-D", "-f", "/etc/lighttpd.conf", "-m", "/usr/lib/lighttpd"])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", "/tmp")
            .stdin(Stdio::null());
        let mut server = Server(cmd.stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap());
        let start = Instant::now();
        // Listening once its log says it started (a connection could reach
        // whoever else holds the port).
        let ended = loop {
            if std::fs::read_to_string(&log_path).is_ok_and(|l| l.contains("server started")) {
                break None;
            }
            if let Some(status) = server.0.try_wait().unwrap() {
                break Some(status);
            }
            assert!(start.elapsed() < Duration::from_secs(20), "lighttpd never listened");
            std::thread::sleep(Duration::from_millis(50));
        };
        let Some(status) = ended else {
            started = Some((server, port));
            break;
        };
        let mut err = String::new();
        if let Some(mut e) = server.0.stderr.take() {
            let _ = std::io::Read::read_to_string(&mut e, &mut err);
        }
        let log = std::fs::read_to_string(&log_path).unwrap_or_default();
        assert!(
            log.contains("Address already in use") || err.contains("Address already in use"),
            "lighttpd ended ({status}) before it listened:\n{err}\n{log}"
        );
    }
    let (server, port) = started.expect("a free port for lighttpd");
    // On a failure, lighttpd's own account of it.
    let result = std::panic::catch_unwind(|| lighttpd_requests(port, &big));
    if let Err(e) = result {
        drop(server);
        eprintln!(
            "--- lighttpd's error log:\n{}",
            std::fs::read_to_string(&log_path).unwrap_or_default()
        );
        std::panic::resume_unwind(e);
    }
    drop(server);
    let log = std::fs::read_to_string(&log_path).unwrap();
    assert!(log.contains("server started") && log.contains("server stopped"), "{log}");
}

/// The requests `debian_lighttpd_serves_files_and_cgi` makes of the server
/// on `port`, which serves `big` as `/big.txt`.
fn lighttpd_requests(port: u16, big: &str) {
    assert_eq!(
        http(port, "GET", "/", ""),
        ("HTTP/1.0 200 OK".into(), b"hello from lighttpd\n".to_vec())
    );
    let (status, body) = http(port, "GET", "/big.txt", "");
    assert_eq!(status, "HTTP/1.0 200 OK");
    assert!(body == big.as_bytes(), "big.txt came back as {} bytes", body.len());
    let (status, body) = http(port, "GET", "/sub/", "");
    assert_eq!(status, "HTTP/1.0 200 OK");
    let listing = String::from_utf8_lossy(&body);
    assert!(listing.contains("Index of /sub/") && listing.contains("a.txt"), "{listing}");
    assert_eq!(http(port, "GET", "/missing", "").0, "HTTP/1.0 404 Not Found");
    // Clients at once.
    let clients: Vec<_> =
        (0..8).map(|_| std::thread::spawn(move || http(port, "GET", "/", "").1)).collect();
    for c in clients {
        assert_eq!(c.join().unwrap(), b"hello from lighttpd\n");
    }
    // CGI, with the database behind it.
    assert_eq!(
        http(port, "POST", "/count.sh", "alice"),
        ("HTTP/1.0 200 OK".into(), b"POST : init,alice\n".to_vec())
    );
    assert_eq!(
        http(port, "GET", "/count.sh?x=1", ""),
        ("HTTP/1.0 200 OK".into(), b"GET x=1: init,alice\n".to_vec())
    );
}

#[test]
fn debian_bash_propagates_exit_status() {
    assert_eq!(run_debian("bash", &["-c", "exit 7"], &[]).status.code(), Some(7));
}

#[test]
fn debian_bash_evaluates_arithmetic() {
    let out = run_debian("bash", &["-c", "x=3; y=4; echo $((x*x + y*y))"], &[]);
    assert_eq!(stdout(&out), "25\n");
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn debian_bash_runs_a_loop() {
    let out = run_debian("bash", &["-c", "for w in a b c; do echo -n \"$w\"; done; echo"], &[]);
    assert_eq!(stdout(&out), "abc\n");
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn asm_hello() {
    for name in ["hello", "hello-pie"] {
        let out = fwe(&asm_guest(name), &[]);
        assert_eq!(stdout(&out), "hello from linux\n", "{name}");
        assert_eq!(out.status.code(), Some(0), "{name}");
    }
}

#[test]
fn asm_exit_status() {
    for name in ["exit42", "exit42-pie"] {
        assert_eq!(fwe(&asm_guest(name), &[]).status.code(), Some(42), "{name}");
    }
}

#[test]
fn asm_unknown_syscall_is_enosys() {
    assert_eq!(fwe(&asm_guest("enosys"), &[]).status.code(), Some(0));
}

#[test]
fn asm_registers_preserved() {
    for name in ["regs", "regs-pie"] {
        let code = fwe(&asm_guest(name), &[]).status.code();
        let meaning = match code {
            Some(0) => "preserved",
            Some(2) => "TPIDR_EL0 lost",
            Some(3) => "a general-purpose register lost",
            _ => "crashed",
        };
        assert_eq!(code, Some(0), "{name}: register state: {meaning}");
    }
}

/// x18 across trapped system calls. Guest uses of x18 are rewritten to a
/// per-thread slot, so this holds regardless of whether the host preserves x18.
#[test]
fn asm_x18_survives_syscalls() {
    assert_eq!(fwe(&asm_guest("x18-pie"), &[]).status.code(), Some(0));
}

/// x18 across preemption alone — the case the custom x18 ABI could not cover on
/// the CI VMs. The rewrite keeps x18 in a slot, so it survives preemption.
#[test]
fn asm_x18_survives_preemption() {
    assert_eq!(fwe(&asm_guest("x18spin-pie"), &[]).status.code(), Some(0));
}

/// x18 spilled to memory (a register-based buffer and a stack slot) and
/// reloaded, across preemption. Exercises the x18 load/store rewrite including
/// the sp-offset adjustment.
#[test]
fn asm_x18_survives_memory_spill() {
    assert_eq!(fwe(&asm_guest("x18mem-pie"), &[]).status.code(), Some(0));
}

/// x18 through the wider data-processing classes (extract, conditional select,
/// multiply-add, divide), across preemption.
#[test]
fn asm_x18_survives_data_processing() {
    assert_eq!(fwe(&asm_guest("x18dp-pie"), &[]).status.code(), Some(0));
}

/// x18 through the remaining load/store addressing modes (unscaled, register
/// offset, pre/post-index, and load/store pair including an sp base), across
/// preemption.
#[test]
fn asm_x18_survives_load_store_addressing() {
    assert_eq!(fwe(&asm_guest("x18ldst-pie"), &[]).status.code(), Some(0));
}

/// x18 read by compare/test branches (cbz/cbnz/tbz/tbnz), across preemption:
/// the branch stub tests the preserved value rather than the hardware x18.
#[test]
fn asm_x18_survives_compare_branches() {
    assert_eq!(fwe(&asm_guest("x18br-pie"), &[]).status.code(), Some(0));
}

/// x18 moved to/from floating-point registers (fmov, scvtf, fcvtzs), across
/// preemption — the form a compiled SIMD scan loop uses.
#[test]
fn asm_x18_survives_fp_moves() {
    assert_eq!(fwe(&asm_guest("x18fp-pie"), &[]).status.code(), Some(0));
}

/// x18 as a PC-relative destination (`adr`) and an indirect-branch target
/// (`blr`/`br`), across preemption.
#[test]
fn asm_x18_pc_relative_and_indirect() {
    assert_eq!(fwe(&asm_guest("x18pc-pie"), &[]).status.code(), Some(0));
}

/// x18 across a signal handler: the handler sees the guest's x18 (which lives
/// in the per-thread slot, not the hardware register) in `uc_mcontext.regs[18]`
/// and the resume pc in `uc_mcontext.pc`, at the arm64 frame offsets; it
/// clobbers x18, and `rt_sigreturn` restores it.
#[test]
fn asm_x18_across_signal_handler() {
    assert_eq!(fwe(&asm_guest("x18sig-pie"), &[]).status.code(), Some(0));
}

/// A thread blocked in `read` on a pipe must not hold the kernel lock, or the
/// thread that writes to the pipe could never make its own system call.
#[test]
fn blocking_read_does_not_stall_writer_thread() {
    for name in ["pipethread", "pipethread-pie"] {
        assert_eq!(fwe(&asm_guest(name), &[]).status.code(), Some(0), "{name}");
    }
}

/// TPIDR_EL0 (the Linux thread pointer) across trapped system calls.
#[test]
fn asm_tpidr_survives_syscalls() {
    for name in ["tpidr", "tpidr-pie"] {
        assert_eq!(fwe(&asm_guest(name), &[]).status.code(), Some(0), "{name}");
    }
}

#[test]
fn rust_hello() {
    let out = fwe(&rust_guest("hello"), &[]);
    assert_eq!(stdout(&out), "hello from rust on linux\n");
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn rust_args_env_and_exit_status() {
    let out = fwe(&rust_guest("args"), &["one", "two words", "exit=7"]);
    let expected = format!(
        "arg[0]={}\narg[1]=one\narg[2]=two words\narg[3]=exit=7\nFWE_GUEST_VAR=from-host\n",
        rust_guest("args").display()
    );
    assert_eq!(stdout(&out), expected);
    assert_eq!(out.status.code(), Some(7));
}

/// A compiled Rust/musl binary exercising heap, sleep, clock and a large
/// allocation. Compiled code uses x18 as a scratch register throughout; the
/// x18 rewrite (every x18-naming instruction in this binary is covered) keeps
/// it correct across preemption and faults with no reliance on the host, so
/// this runs unconditionally.
#[test]
fn rust_runtime_services() {
    let out = fwe(&rust_guest("sysinfo"), &[]);
    assert_eq!(
        stdout(&out),
        "heap ok: 10000 entries, 314616 bytes\nsleep ok: true\nclock ok: true\nlarge allocation ok: true\n"
    );
    assert_eq!(out.status.code(), Some(0));
}

/// Without the hypervisor entitlement (the plain test build is unsigned), a
/// program linked below 4 GiB is refused with an explanation.
#[test]
fn low_link_address_needs_the_hypervisor() {
    let out = fwe(&asm_guest("hello-low"), &[]);
    assert_eq!(out.status.code(), Some(126));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("below 4 GiB") && err.contains("entitlement"), "{err}");
}

#[test]
fn rejects_non_elf() {
    let this_file = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/guests.rs");
    let out = Command::new(env!("CARGO_BIN_EXE_fwe")).arg(this_file).output().unwrap();
    assert_eq!(out.status.code(), Some(126));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not an ELF file"));
}

/// FP/SIMD state across a signal handler: the frame carries an
/// `fpsimd_context` record with the interrupted registers and FPCR, and what
/// the handler does to them is undone by `rt_sigreturn`.
#[test]
fn fp_state_survives_a_signal_handler() {
    for name in ["fpsig", "fpsig-pie"] {
        assert_eq!(fwe(&asm_guest(name), &[]).status.code(), Some(0), "{name}");
    }
}

/// Run one scenario of the `signals` guest and return what it printed.
fn signals(scenario: &str) -> String {
    let out = fwe(&rust_guest("signals"), &[scenario]);
    assert_eq!(out.status.code(), Some(0), "{scenario}: {out:?}");
    stdout(&out)
}

/// `kill` reaches another process: a parent kills a child blocked in
/// `pause`, and `wait4` reports the signal.
#[test]
fn kill_reaches_another_process() {
    assert_eq!(signals("kill-child"), "killed by 15\n");
}

/// A flood of signals, from other processes and between the guest's own
/// threads (as Go's runtime preempts them), while those threads make
/// system calls: fwe's handlers do not nest without bound on the signal
/// stack (one that interrupts fwe's own code only records the signal);
/// before, the process hung in nested handlers or its signal stack ran out.
#[test]
fn signal_flood_during_system_calls() {
    // What it checks is that the storm is survived, not how fast: on a
    // small machine running other tests beside it, it takes a while.
    let out = fwe_within(&rust_guest("signals"), &["storm"], Duration::from_secs(60));
    assert_eq!(out.status.code(), Some(0), "storm: {out:?}");
    assert_eq!(stdout(&out), "survived: true calls: true\n");
}

/// A signal from another process reaches a guest handler (through the host),
/// with the sender's pid in `siginfo`, and wakes `sigsuspend`.
#[test]
fn signal_from_child_reaches_parent_handler() {
    assert_eq!(signals("notify-parent"), "SIGUSR1 from child: true\nexited 0\n");
}

/// A signal the guest blocks stays pending with its sender, as on Linux,
/// though macOS forgets the sender of a signal it holds blocked: taken by a
/// handler and by `sigtimedwait` after the sender has exited.
#[test]
fn blocked_signal_keeps_its_sender() {
    assert_eq!(signals("notify-parent-blocked"), "SIGUSR1 from child: true\nexited 0\n");
    assert_eq!(signals("sigwait-from-child"), "took 12 from child: true\nexited 0\n");
}

/// Signals the guest blocks, routed as Linux routes them: one sent with
/// `tgkill` waits for its thread, which blocks it, though another thread
/// accepts it; one with a default action that ends the process stays
/// pending while every thread blocks it; and a stop reports its signal.
#[test]
fn blocked_signals_routed_as_on_linux() {
    assert_eq!(
        signals("tgkill-blocked"),
        "held for the blocking thread: true, then handled on it: true\n"
    );
    assert_eq!(signals("default-blocked"), "still running, pending: true\n");
    assert_eq!(signals("stop-tstp"), "stopped: true, by 20\nkilled by 9\n");
}

/// A child's exit raises `SIGCHLD` in the parent, carrying the child's pid
/// and exit status — also when the signal waited blocked until after the
/// child was gone, which macOS reports with an empty `siginfo`.
#[test]
fn sigchld_reaches_handler_with_status() {
    for scenario in ["sigchld", "sigchld-late"] {
        assert_eq!(
            signals(scenario),
            "SIGCHLD from child: true, status 3\nexited 3\n",
            "{scenario}"
        );
    }
}

/// A timer signal interrupts a blocking `read`: with `SA_RESTART` the read
/// resumes and returns the data that arrives later; without it, `EINTR`.
#[test]
fn interrupted_read_restarts_only_with_sa_restart() {
    assert_eq!(signals("restart"), "read: 1 byte, handler ran 1 time(s)\n");
    assert_eq!(signals("no-restart"), "read: errno 4, handler ran 1 time(s)\n");
}

/// `pause` (a `ppoll` with no descriptors) returns `EINTR` once a handler
/// ran, here for an `ITIMER_REAL` timer.
#[test]
fn pause_returns_after_timer_handler() {
    assert_eq!(signals("pause"), "pause: -1 errno 4, handler ran: true\n");
}

/// Signal masks are per thread: a signal sent to the process is handled on
/// the thread that does not block it.
#[test]
fn process_signal_goes_to_unblocked_thread() {
    assert_eq!(signals("thread-mask"), "handled on the unblocked thread: true\n");
}

/// A process signal sent while every thread blocks it reaches the thread
/// that unblocks it first, though macOS parks it on the main thread, which
/// never does.
#[test]
fn signal_blocked_everywhere_goes_to_the_thread_that_unblocks_it() {
    assert_eq!(signals("parked"), "parked signal handled on the unblocked thread: true\n");
}

/// `tgkill` aims at one thread and interrupts its blocking call, both for a
/// signal the host has and for a real-time one it does not.
#[test]
fn tgkill_interrupts_one_thread() {
    assert_eq!(
        signals("tgkill"),
        "signal 12: reader EINTR, handled on it: true\nsignal 40: reader EINTR, handled on it: true\n"
    );
}

/// A real-time signal (no host equivalent) sent to the process itself.
#[test]
fn realtime_signal_to_self() {
    assert_eq!(signals("rt-self"), "handled: 1, signal 40\n");
}

/// `SIGSEGV`, `SIGFPE` and `SIGTRAP` that a process sends itself reach its
/// handlers (the host cannot tell them from faults, so they are emulated),
/// and an ignored `SIGTRAP` is ignored.
#[test]
fn sent_fault_signals_reach_handlers() {
    assert_eq!(
        signals("raise-faults"),
        "signal 11: handled 1\nsignal 8: handled 1\nsignal 5: handled 1\nignored SIGTRAP: still running\n"
    );
}

/// A real-time signal sent to the process wakes the thread that waits for
/// it.
#[test]
fn realtime_signal_reaches_waiting_thread() {
    assert_eq!(signals("rt-to-waiter"), "waiter took 40\n");
}

/// A signal a signalfd reads gets there even when the host hands it to a
/// thread blocked on a futex rather than to the reader.
#[test]
fn signalfd_gets_signal_landing_on_futex_waiter() {
    assert_eq!(signals("signalfd-join"), "reader got 128 bytes for signal 10\n");
}

/// A SIGTRAP from another process reaches one busy making system calls,
/// whose own traps are SIGTRAPs too (which the host would merge it with).
#[test]
fn sigtrap_from_another_process_is_not_lost() {
    assert_eq!(signals("trap-from-other"), "SIGTRAP from another process: lost 0 of 100\n");
}

/// `ppoll` waits under the mask it is given, so a signal blocked outside it
/// interrupts it and runs the handler.
#[test]
fn ppoll_applies_its_signal_mask() {
    assert_eq!(signals("ppoll-mask"), "ppoll -1 errno 4, handled 1\n");
}

/// The alternate signal stack's modes as Linux takes them: `SS_ONSTACK`
/// and `SS_DISABLE` accepted, and `SS_AUTODISARM` disabling the stack
/// while a handler runs on it.
#[test]
fn the_alternate_stack_takes_linuxs_modes() {
    assert_eq!(
        signals("altstack"),
        "onstack 0, disable 0 disabled true, autodisarm 0: \
         handled true, on it true, disarmed in it true, restored true\n"
    );
}

/// With the default disposition, writing to a pipe without a reader kills
/// the writer with `SIGPIPE`, as on Linux.
#[test]
fn sigpipe_kills_writer_by_default() {
    use std::os::unix::process::ExitStatusExt;
    let out = fwe(&rust_guest("signals"), &["sigpipe"]);
    assert_eq!(out.status.signal(), Some(libc::SIGPIPE), "{out:?}");
    assert_eq!(stdout(&out), "");
}

/// A signal ignored by whoever started fwe stays ignored in the guest, as an
/// ignored disposition survives a Linux `execve` (`nohup`, background jobs).
#[test]
fn ignored_signals_are_inherited() {
    use std::os::unix::process::CommandExt;
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fwe"));
    cmd.arg(rust_guest("signals")).arg("inherited");
    // SAFETY: only async-signal-safe calls between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            libc::signal(libc::SIGINT, libc::SIG_IGN);
            libc::signal(libc::SIGHUP, libc::SIG_DFL);
            Ok(())
        });
    }
    let out = run_bounded(cmd);
    assert_eq!(stdout(&out), "signal 1: default\nsignal 2: ignored\n", "{out:?}");
}

/// `sigtimedwait` takes a blocked pending signal without running a handler,
/// then times out with `EAGAIN`.
#[test]
fn sigtimedwait_takes_pending_then_times_out() {
    assert_eq!(signals("sigtimedwait"), "took 12, code 0\nthen -1 errno EAGAIN\n");
}

/// `std::process::Command` spawns through musl's `posix_spawn`, a
/// `CLONE_VM | CLONE_VFORK` clone that execs the same fixed-address binary:
/// it needs the vfork form of `clone` and an `execve` that discards the old
/// address space. Both with piped and with inherited standard I/O.
#[test]
fn command_spawns_a_child_program() {
    assert_eq!(
        signals("spawn"),
        "child said: hello from the spawned child\nchild exit status: 0\n"
    );
    assert_eq!(signals("spawn-status"), "hello from the spawned child\nchild exit status: 0\n");
}

/// `vfork` then `execve` in the child, and `execve` of the running binary
/// itself: the new image is loaded where the old one was.
#[test]
fn exec_replaces_the_address_space() {
    assert_eq!(signals("vfork-exec"), "hello from the spawned child\nexited 0\n");
    assert_eq!(signals("exec-self"), "hello from the spawned child\n");
}

/// Writable and executable memory, as JIT compilers use it (macOS never maps
/// memory so): code written there runs, runs again after being rewritten in
/// place, and may make system calls; `mrs ctr_el0`, which macOS traps at
/// EL0, reads a cache type.
#[test]
fn jit_code_runs_from_writable_executable_memory() {
    assert_eq!(signals("jit"), JIT);
}

/// What the `jit` scenario prints.
const JIT: &str = "jit: 42 7, getpid matches: true\nctr_el0 has cache lines: true\n";

/// `fork` from a process with a second thread running: the child has just
/// the forking thread and runs normally.
#[test]
fn fork_from_a_threaded_process() {
    assert_eq!(signals("threaded-fork"), "child of a threaded parent\nexited 5\n");
}

/// A fork child reading a pipe sees its end once the parent closes its
/// write end.
#[test]
fn fork_child_sees_the_end_of_a_pipe() {
    assert_eq!(signals("fork-pipe"), "child read 5 bytes, then the end\nexited 0\n");
}

/// A fork while another thread writes sees one instant of the process: the
/// threads running guest code are stopped while the host fork copies memory.
#[test]
fn fork_sees_one_instant_of_a_threaded_process() {
    assert_eq!(signals("fork-snapshot"), "consistent snapshots: 8 of 8\n");
}

/// What a vfork child writes the parent sees: glibc's `posix_spawn` reports
/// a failed exec through the memory it shares with its child (so it returns
/// `ENOENT`), and a plain `vfork` child's writes to a global and to the
/// parent's stack are there once it exits.
#[test]
fn vfork_child_shares_memory() {
    let prog = build_c_dynamic("dynspawn", Libc::Glibc, true);
    let root = libc_rootfs(Libc::Glibc, "glibc-spawn");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fwe"));
    cmd.arg("--root").arg(&root).arg(&prog);
    let out = run_bounded(cmd);
    eprintln!("--- dynspawn stderr:\n{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(stdout(&out), VFORK_SHARES);
    assert_eq!(out.status.code(), Some(0));
    let _ = std::fs::remove_dir_all(&root);
}

/// What `dynspawn` prints when the vfork child shares memory.
const VFORK_SHARES: &str =
    "posix_spawn of a missing program: 2\nvfork child's writes seen: 42 7, status 0\n";

/// A fork child sees the parent's memory as it was at the fork, and neither
/// side sees the other's later private writes; shared memory stays shared.
/// It can use the `epoll` and `timerfd` descriptors it inherited, which on
/// macOS are kqueues that a child does not inherit and fwe rebuilds.
#[test]
fn fork_copies_memory_and_keeps_descriptors() {
    assert_eq!(
        signals("fork-cow"),
        "child sees the fork-time memory: true\nparent's later writes unseen: true\n\
         child's writes unseen: true\nshared memory shared: true\nexited 0\n"
    );
    assert_eq!(
        signals("fork-epoll"),
        "child's epoll: 1 event(s), data 42\nchild's timer fired: true\nexited 0\n"
    );
    assert_eq!(signals("fork-timerfd"), FORK_TIMERFD);
}

/// What `signals fork-timerfd` prints.
const FORK_TIMERFD: &str = "parent read its expiration: true\n\
                            child reads the unread expiration: true\n\
                            child finds the read one empty: true\nexited 0\n";

/// `clone3` in its fork form, and `execveat` relative to a directory, of the
/// open file itself, and refusing a symbolic link under
/// `AT_SYMLINK_NOFOLLOW`.
#[test]
fn clone3_fork_and_execveat() {
    assert_eq!(signals("clone3-fork"), "clone3 child\nexited 3\n");
    assert_eq!(
        signals("execveat"),
        "hello from the spawned child\nrelative to a directory: exited 0\n\
         hello from the spawned child\nthe open file itself: exited 0\n\
         symlink with AT_SYMLINK_NOFOLLOW: -1, errno 40\nunknown flag: -1, errno 22\n"
    );
}

/// `execve` keeps the virtual credentials (the saved IDs becoming the
/// effective ones), `RLIMIT_NOFILE` and the umask, both when the program is
/// replaced in place and when fwe re-executes itself (another thread alive).
#[test]
fn exec_keeps_credentials_and_limits() {
    let want = "uids [10, 11, 11] gids [20, 21, 21] groups [7] nofile [300, 400] umask 27\n";
    assert_eq!(signals("exec-keeps-ids"), want);
    let out = fwe(&rust_guest("signals"), &["exec-keeps-ids", "threaded"]);
    assert_eq!(stdout(&out), want);
}

/// `waitid` reports an exit and a kill as `siginfo`.
#[test]
fn waitid_reports_exit_and_kill() {
    assert_eq!(
        signals("waitid"),
        "exited: true, status 6, pid matches: true\nkilled: true, signal 9\n"
    );
}

/// `wait4` and `getrusage` report resource usage in Linux units.
#[test]
fn rusage_in_linux_units() {
    assert_eq!(
        signals("rusage"),
        "child used cpu: true\nchild maxrss plausible: true\nown maxrss plausible: true\n"
    );
}

/// Real Debian bash: `kill` on a background job, and a `trap` handler for a
/// signal the shell sends itself.
#[test]
fn debian_bash_kills_a_background_job() {
    let out = run_debian(
        "bash",
        &["-c", "f() { while :; do :; done; }; f & p=$!; kill $p; wait $p; echo status=$?"],
        &[],
    );
    assert_eq!(stdout(&out), "status=143\n");
}

#[test]
fn debian_bash_runs_trap_handlers() {
    let out = run_debian(
        "bash",
        &[
            "-c",
            "trap 'echo trapped' USR1; kill -USR1 $$; trap 'echo reaped' CHLD; (exit 0); echo end",
        ],
        &[],
    );
    assert_eq!(stdout(&out), "trapped\nreaped\nend\n");
}

/// Run one scenario of the `namespaces` guest in a root filesystem of its
/// own (`/mnt`, `/tmp`, and `/newroot` with `etc/marker` and `proc`) and
/// return its output.
fn namespaces(scenario: &str) -> String {
    let root = std::env::temp_dir().join(format!("fwe-ns-{}-{scenario}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    for d in ["mnt", "tmp", "newroot/etc", "newroot/proc"] {
        std::fs::create_dir_all(root.join(d)).unwrap();
    }
    std::fs::write(root.join("newroot/etc/marker"), "new\n").unwrap();
    std::fs::copy(rust_guest("namespaces"), root.join("namespaces")).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fwe"));
    cmd.arg("--strace=failures")
        .arg("--root")
        .arg(&root)
        .arg(root.join("namespaces"))
        .arg(scenario);
    let out = run_bounded(cmd);
    eprintln!("--- namespaces {scenario} stderr:\n{}", String::from_utf8_lossy(&out.stderr));
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(out.status.code(), Some(0), "{scenario}: {}", stdout(&out));
    stdout(&out)
}

/// A UTS namespace has its own host name; the initial one's is the host's,
/// which the guest cannot change.
#[test]
fn uts_namespace_has_its_own_name() {
    assert_eq!(
        namespaces("uts"),
        "inside: box\nproc: box\nchild exited 0, outside unchanged: true\n\
         outside sethostname: -1 errno 1\n"
    );
}

/// A pid namespace numbers its processes from 1: its init has parent 0,
/// its children are numbered and reaped there, and its parent sees it by
/// a pid of its own.
#[test]
fn pid_namespace_numbers_from_one() {
    assert_eq!(
        namespaces("pid"),
        "child: pid 1 ppid 0\ngrandchild: pid 2 ppid 1\nforked 2\nkill: 0\n\
         reaped 2, killed by 9\nno such pid: -1 errno 3\n\
         parent: child true reaped as itself, exited 7\n"
    );
}

/// A mount made in a mount namespace is seen there only; a read-only bind
/// mount refuses writes.
#[test]
fn mounts_stay_in_their_namespace() {
    assert_eq!(
        namespaces("mount"),
        "mount tmpfs: 0\ninside: in tmpfs true\nthrough the bind: in tmpfs\n\
         write there: EROFS true\numount: 0\nchild exited 0, outside: false false\n"
    );
}

/// The root a container runtime makes: `pivot_root(".", ".")` onto a bind
/// mount of the new root, then the old root unmounted.
#[test]
fn pivot_root_makes_a_container_root() {
    assert_eq!(
        namespaces("pivot"),
        "pivot: 0\numount old root: 0\nmarker: new\nold root gone: true\nproc: true\n\
         mounts: / /proc\nchild exited 0\n"
    );
}

/// A network namespace has a loopback interface, down until brought up,
/// and ports of its own: a stream within it works, a port is taken once,
/// other addresses are unreachable, and a port it holds is free outside.
#[test]
fn network_namespace_has_its_own_loopback() {
    assert_eq!(
        namespaces("net"),
        "lo down: true\nlo up: true\nbound: 127.0.0.1:18080\nclient's peer: 127.0.0.1:18080\n\
         served: ping\ntaken: true\nelsewhere: true\nnobody there: true\nchild exited 0\n"
    );
    assert_eq!(namespaces("net-outside"), "inside: 127.0.0.1:18082\noutside too: true\n");
}

/// A thread's own root, mounts and network namespace: a thread that
/// unshares `CLONE_FS` and the mount namespace mounts and changes its root
/// alone; one that unshares the network namespace binds a port there that
/// the process binds too, until it joins the process's again; what a
/// thread that shares them sets (working directory, umask), the others
/// have; and the mount namespace is not joined while the root is shared.
#[test]
fn threads_have_their_own_root_and_namespaces() {
    assert_eq!(
        namespaces("threads"),
        "thread: unshare 0 private 0 tmpfs 0 true chroot 0 marker new new\n\
         others: root kept true, /mnt not mounted true\nshared: umask 77 cwd /tmp\n\
         net: thread bound true, process too true\nback: 0, port taken true\n\
         setns mnt with threads: -1 errno 22\n"
    );
}

/// A network namespace kept by a bind mount of its file, as Docker keeps
/// a container's: made on a thread, bound by the thread's
/// `/proc/<pid>/task/<tid>/ns/net`, shown as nsfs, its inode the
/// namespace's; the process and a child join it through the file and share
/// its ports; unmounted, the path is the plain file again.
#[test]
fn namespace_file_bound_to_a_path() {
    assert_eq!(
        namespaces("nsbind"),
        "bind: 0, back 0\ninode is the namespace's: true\nmountinfo: true\n\
         joined: 0, bound true\nchild joined: 0, port taken true\nchild exited 0\n\
         umount: 0, a plain file again: -1 errno 22\n"
    );
}

/// A directory of a bind mount of an overlay, opened, reaches what is
/// mounted below the bind: runc makes `dev/pts` this way in the tmpfs it
/// put on a container's `dev`, the root a bind of an overlay (BuildKit's).
#[test]
fn overlay_bind_directory_reaches_mounts_below() {
    assert_eq!(
        namespaces("ovlbind"),
        "mounts: 0 0 0\nmkdir: 0, in the tmpfs true, not the overlay's true\nchild exited 0\n"
    );
}

/// A user namespace: unmapped until its maps are written, once, under
/// Linux's rules (the process itself its own id only, setgroups denied
/// first; its parent, privileged outside, anything), with every capability
/// inside.
#[test]
fn user_namespace_maps_ids() {
    assert_eq!(
        namespaces("user"),
        "unmapped: 65534 65534\nCapEff:\t000001ffffffffff\n\
         gid_map before setgroups: Err(1)\nsetgroups: Ok(())\n\
         uid_map, more than one's own: Err(1)\nuid_map: Ok(())\ngid_map: Ok(())\nagain: Err(1)\n\
         mapped: 0 0\nsetuid to an unmapped id: -1 errno 22\n\
         map:          0          0          1\nchild exited 0\n\
         parent wrote the map: true\nin child: uid 0, setuid(5) 0, uid 5\n"
    );
}

/// `chroot` confines paths; a `clone` makes the namespaces it asks for.
#[test]
fn chroot_and_clone_namespaces() {
    assert_eq!(
        namespaces("chroot"),
        "chroot: 0\nmarker: new\ncannot leave: new\nchild exited 0\nnew namespaces: true\n\
         own: uts:[4026531838] pid:[4026531836]\n"
    );
}

/// Run one scenario of the `sysvipc` guest and return its output.
fn sysvipc(scenario: &str) -> String {
    let out = fwe(&rust_guest("sysvipc"), &[scenario]);
    assert_eq!(out.status.code(), Some(0), "{scenario}: {out:?}");
    stdout(&out)
}

/// System V IPC between processes, as on Linux: a segment a child writes
/// is what its parent reads (and counts the parent's attachment), a
/// semaphore a child posts ends its parent's wait (whose operation is the
/// last on it),
/// a child's `SEM_UNDO` post is undone as it ends, and messages go both
/// ways by type.
#[test]
fn sysv_ipc_between_processes() {
    assert_eq!(
        sysvipc("processes"),
        "shm: written by the child, attached 1\n\
         sem: waited for the child's post: true, last by this process: true\n\
         sem: after the child's undo: 0\n\
         msg: got ping (type 3)\n\
         msg: left on the queue: 1\n"
    );
}

/// A semaphore one thread waits on and another posts: the wait holds
/// nothing the post needs.
#[test]
fn sysv_semaphore_between_threads() {
    assert_eq!(sysvipc("threads"), "thread: waited for the other thread's post: true\n");
}

/// What the `maps` guest observes of its own mappings.
const MAPS: &str = "program: listed with its code executable: true\n\
    stack: rw-p\n\
    file: r--p /memfd:maps-test (deleted), from page 1, 2 pages\n\
    shared: rw-s r--s rw-s\n\
    mlock: 0, locked pages resident: true, smaps Locked true, Rss true\n\
    status: VmLck covers it: true\n\
    query: 0, the program's code: true, executable: true\n\
    query: build ID of 20 bytes, the file's: true\n\
    query: a short build ID buffer: -1 true\n\
    unmapped: listed 0\n\
    other: an idle fork child lists what it inherited: true\n\
    other: r--p /memfd:maps-other (deleted), from page 1\n\
    other: its filled memory resident: true\n\
    other: query 0: /memfd:maps-other (deleted), offset 1 pages\n\
    other: gone with it: true\n";

/// `/proc/self/maps` and `smaps` list the program, its stack, a file
/// mapped from an offset, protections changed in the middle of a mapping
/// and locked memory; `mincore`, `VmLck` and `PROCMAP_QUERY` agree, and an
/// unmapped range is gone.
#[test]
fn proc_maps_lists_the_mappings() {
    let out = fwe(&rust_guest("maps"), &[]);
    assert_eq!(stdout(&out), MAPS, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0));
}

/// What the `calls` guest prints.
const CALLS: &str = "splice: 5, offset 7, position 10\n\
    tee: 3; first pipe 23456, second 234\n\
    vmsplice: 8, read vmsplice\n\
    splice from an empty pipe: true\n\
    splice between files: true\n\
    personality: was 0, now 0x20000, release 2.6: true\n\
    sched: set 0, get 0, policy 2, priority 10\n\
    child's policy: 2\n\
    clock: read 0, set refused true\n\
    pipe's filesystem: 0, pipefs true; statx reserved bit refused true\n\
    working directory renamed: followed true\n\
    a /proc link's O_PATH descriptor: a link true, reads it true; unknown fstatat flag refused true\n";

/// Data moved through pipes (`splice` from a file's offset, `tee`,
/// `vmsplice`), the personality, a scheduling policy a fork child
/// inherits, and a clock that is read but not set.
#[test]
fn kernel_calls_move_data_and_keep_settings() {
    let out = fwe(&rust_guest("calls"), &[]);
    assert_eq!(stdout(&out), CALLS, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0));
}

/// What the `mqueue` guest prints.
const MQUEUE: &str = "open: true, maxmsg 4, msgsize 32, mode 100640, close-on-exec true\n\
    status: QSIZE:14         NOTIFY:0     SIGNO:0     NOTIFY_PID:0\n\
    listed: true, file the same: true\n\
    received: high/9 mid/5 low/1 low2/1\n\
    empty: true\n\
    signal: registered 0, shown true, came true, mesgq true, from the sender true, value 0x5eed\n\
    real-time signal: registered 0, came true, mesgq true, from the sender true, value 0x7e47\n\
    thread: registered 0, came true, value 0x7ead\n\
    unlinked: name gone true, still sends 0, receives kept\n\
    made again: true, empty true\n";

const PIDFD: &str = "self: cloexec true, link anon_inode:[pidfd], fdinfo pid true\n\
    errors: -1 true, flags true, none true\n\
    child: nonblock true, ended early false, waitid EAGAIN, info 0 pid true exit asked false\n\
    ended: readable true, waitid 0 status 7, info 0 exit true code 0x700, without exit ESRCH, signal ESRCH\n\
    signal: sent 0, another number EINVAL, child saw the value true\n\
    clone3: pidfd true, cloexec true, epoll 1 data 9, waitid 0 status 5\n\
    inherited: the fork child saw its sibling end true, reaped 0\n\
    thread: without PIDFD_THREAD EINVAL, ended while running false, ended after true\n\
    getfd: got true, cloexec true, file \"from the child, and the parent\", not open EBADF, flags EINVAL, not a pidfd EBADF\n\
    namespaces: uts descriptor true, setns joined it true\n\
    not a pidfd: signal EBADF, waitid EBADF\n";

/// Process descriptors: opened, polled and waited for, signalled through,
/// made by `clone3`, inherited by a fork child, of a thread, taken a
/// descriptor from, and a way into a process's namespaces.
#[test]
fn process_descriptors_name_processes() {
    let out = fwe(&rust_guest("pidfd"), &[]);
    assert_eq!(stdout(&out), PIDFD, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0));
}

/// What the `ptrace` guest prints.
const PTRACE: &str = "stop: signal 19\n\
    peek: true\n\
    regs: 272 bytes, pc near the code true\n\
    thread pointer: set true\n\
    poke: exit 7\n\
    syscalls: write stopped at entry true, its result -9\n\
    fork: events 1, new child stopped 1, exit events 2, exits 2\n\
    thread: events 1, new thread stopped 1, its end 1, exit 5\n\
    waitid: signal true, trapped true, status 19\n\
    step: exit 21, stepped true\n\
    attach: listed true, tgkill true, attached true, signal 19, pc true, detached true\n\
    robust lists: process true, thread true\n\
    breakpoint: signal 5, at work true, argument 10, exit 21\n";

/// ptrace: a traced child stops for a signal, has its memory read and
/// written and its registers read, stops at a system call's entry and
/// exit, has a fork and a thread it makes followed, is reported by
/// `waitid`, runs one
/// instruction at a time to its end and stops at a breakpoint.
#[test]
fn ptrace_traces_a_child() {
    let out = fwe(&rust_guest("ptrace"), &[]);
    assert_eq!(stdout(&out), PTRACE, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0));
}

/// What the `debugger` guest prints.
const DEBUGGER: &str = "exec: alternate true, entry then event then exit true\n\
    seize: 0, running true\n\
    interrupt: 0, stopped true, event stop true\n\
    sigmask: get 0, SIGUSR1 blocked true, set 0, now true\n\
    mem: read true, write true\n\
    auxv: entry true\n\
    syscall info: size true, entry true, number 173, exit true\n\
    group stop: delivery true, event true, listen 0, stays true, continued true\n\
    killed: true\n";

/// What debuggers ask of ptrace beyond its basics: a seized child runs
/// on until interrupted, which stops it with an event stop; the system
/// call it stops at is described; its signal mask is read and set; a
/// group-stop is an event stop, listened to until `SIGCONT`; and its
/// memory is read and written through `/proc/<pid>/mem`.
#[test]
fn ptrace_serves_debuggers() {
    let out = fwe(&rust_guest("debugger"), &[]);
    assert_eq!(stdout(&out), DEBUGGER, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0));
}

/// What the `robust` guest prints.
const ROBUST: &str = "exited holder: owner dead true, recovered true\n\
    killed holder: signal 15, owner dead true, recovered true\n\
    thread holder: started true, owner dead true, recovered true\n";

/// Robust mutexes whose holder ends without unlocking: a process that
/// exits or is killed, and a thread that ends with the raw `exit` call,
/// a waiter woken. The next to lock each learns its owner died.
#[test]
fn robust_mutexes_report_a_dead_owner() {
    let out = fwe(&rust_guest("robust"), &[]);
    assert_eq!(stdout(&out), ROBUST, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0));
}

/// POSIX message queues: messages by priority, the status line, a queue
/// that outlives its name, and the notifications another process's
/// message sets off (a signal with the value and sender, and the C
/// library's notification thread, through a netlink socket).
#[test]
fn message_queues_deliver_and_notify() {
    let out = fwe(&rust_guest("mqueue"), &[]);
    assert_eq!(stdout(&out), MQUEUE, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0));
}

/// What the `mountapi` guest prints.
const MOUNTAPI: &str = "fsopen: config 0, bogus -1, logged \"e tmpfs: Unknown parameter 'bogus'\", create 0, attached 0\n\
    mounted: options rw,noexec,relatime\n\
    statmount: 0, same id true, type tmpfs, point true\n\
    listmount: listed true\n\
    beneath: 0, top first true, then the copy true\n\
    fspick: 0, read-only true, then rw\n\
    mount_setattr: 0, nodev true, shared true\n\
    propagation: into the copied namespace true, unmount too true\n\
    enforced: nodev true, noexec true (mprotect too true), nosymfollow true\n\
    unmount: busy refused true, expire marks true, then unmounts true\n\
    atime: noatime keeps true, strictatime moves true, remount keeps the mode true\n\
    device bind: 0, a device true, reads empty true\n";

/// The new mount API: a tmpfs made through a filesystem context and
/// attached from a detached mount, a detached copy attached beneath
/// another mount, `fspick`, `mount_setattr`, `statx`, `statmount` and
/// `listmount` agreeing on the mount, a mount under a shared one
/// propagating into a copied namespace, the `nodev`, `noexec` and
/// `nosymfollow` flags acted on, and a busy mount refused.
#[test]
fn the_new_mount_api_makes_and_attaches_mounts() {
    let out = fwe(&rust_guest("mountapi"), &[]);
    assert_eq!(stdout(&out), MOUNTAPI, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0));
}

/// What the `nsfd` guest prints.
const NSFD: &str = "open: true, inode is the link's true, read refused true\n\
    nstype 0x4000000, parent of a UTS namespace refused true\n\
    setns: 0, own name true, back true\n\
    wrong type refused true\n";

/// Namespace descriptors: `/proc/self/ns/uts` opened as nsfs shows it,
/// the `NS_GET_*` requests, and `setns` back into the namespace it names.
#[test]
fn namespace_descriptors_name_and_join_namespaces() {
    let out = fwe(&rust_guest("nsfd"), &[]);
    assert_eq!(stdout(&out), NSFD, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0));
}

/// What the `inotify` guest prints.
const INOTIFY: &str = "watch: true, nothing yet true\n\
    ready true: create a, open a, modify a, close_write a, moved_from a, moved_to b, delete b\n\
    move cookies paired true\n\
    exit closes: create c, open c, modify c, close_write c\n\
    exchange: moved_from c, moved_to d, moved_from d, moved_to c\n\
    fdinfo lists the watch true\n\
    removed 0: ignored true\n";

/// What the `filectl` guest prints.
const FILECTL: &str = "created: 1, then 0\n\
    ofd: locked 0, other open refused true, released through a duplicate 0, then 0\n\
    io signal: the chosen one, for the descriptor true\n\
    lease: set 0, broken true, to read, downgraded 0, the other open done true\n";

/// `fcntl` on open files: open-file-description locks, `F_CREATED_QUERY`,
/// an `F_SETSIG` signal for `SIGIO`, and a lease another process's open
/// breaks.
#[test]
fn file_control_locks_signals_and_leases() {
    let out = fwe(&rust_guest("filectl"), &[]);
    assert_eq!(stdout(&out), FILECTL, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0));
}

/// The same in the VM (see [`file_control_locks_signals_and_leases`]).
#[test]
fn hv_file_control_locks_signals_and_leases() {
    let Some(out) = fwe_hv(&rust_low_guest("filectl"), &[]) else { return };
    assert_eq!(stdout(&out), FILECTL, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0));
}

/// What the `procsig` guest prints, the memory-sharing line aside.
const PROCSIG: &str = "queued to -1: true\n\
    real-time to another: sent 0, taken with its value true\n\
    signal 16 at once: (16, false)\n\
    signal 8 at once: (8, false)\n\
    signal 4 at once: (4, false)\n\
    core of a fault: (11, true), an ELF core true\n\
    core of SIGABRT: (6, true), an ELF core true\n\
    end told with: SIGUSR2, reaped true\n\
    blocked SIGCHLD kept: true\n\
    memory shared: {shared}\n\
    cpu limit: SIGXCPU true, then true\n\
    timer slack: 70000, shown 70000, the child's true\n\
    parent-death signal: the orphan ended true\n\
    and not before: (0, false)\n";

/// Signals between processes and how processes end: a queued real-time
/// signal, `rt_sigqueueinfo` to -1 refused, signals the moment a child is
/// forked, core dumps, a clone's own exit signal, a blocked `SIGCHLD` kept
/// pending at its default action, a child sharing the
/// memory, the hard CPU limit and an inherited timer slack.
#[test]
fn process_signals_and_ends() {
    let out = fwe(&rust_guest("procsig"), &[]);
    let expected = PROCSIG.replace("{shared}", "true");
    assert_eq!(stdout(&out), expected, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0));
}

/// The same in the VM (see [`process_signals_and_ends`]), where a child
/// sharing the memory while both run is refused: its pages would be in
/// two VMs at once.
#[test]
fn hv_process_signals_and_ends() {
    let Some(out) = fwe_hv(&rust_low_guest("procsig"), &[]) else { return };
    let expected = PROCSIG.replace("{shared}", "refused");
    assert_eq!(stdout(&out), expected, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0));
}

/// What the `calls2` guest prints.
const CALLS2: &str = "openat2: plain true, beneath ../ true, no symlinks true, in root true\n\
    epoll_pwait2: none 0 after the timeout true, then 1 with 7\n\
    mseal: 0, munmap refused true, mprotect refused true\n\
    futex_waitv: woken on 1\n\
    remap_file_pages: 0, first page showed 0, now 3\n";

/// Newer calls: `openat2`'s resolve rules, `epoll_pwait2`, `mseal`,
/// `futex_waitv` and `remap_file_pages`.
#[test]
fn newer_calls() {
    let out = fwe(&rust_guest("calls2"), &[]);
    assert_eq!(stdout(&out), CALLS2, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0));
}

/// The same in the VM (see [`newer_calls`]).
#[test]
fn hv_newer_calls() {
    let Some(out) = fwe_hv(&rust_low_guest("calls2"), &[]) else { return };
    assert_eq!(stdout(&out), CALLS2, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0));
}

/// What the `calls3` guest prints.
const CALLS3: &str = "aio: setup 0, submitted 1 1, events 2, wrote 12 read 12, same true\n\
    aio poll: before 0, after 1 with data 3 res 1, eventfd 1\n\
    aio destroy: 0, again refused true\n\
    acct: on 0, off 0, record true, version 3, exit status 0x300, forked true\n\
    dnotify: 2 signals, parent's true, inner's true\n\
    real-time queue: [1, 2, 3]\n\
    file attributes: set 0, get 0, no-dump true\n\
    lsm: 2 modules, ids 100 110, size 16\n\
    sync: 0, syncfs 0, file/ ENOTDIR\n\
    msg_next_id: id true, then -1\n\
    process_vm: read 8 bytes 0x1234, wrote 8, child saw 0x99\n\
    landlock: abi 6, restricted true, inside read true, outside EACCES true\n\
    low port: named true, reached true true, accepted true, bound again true\n";

/// More calls: native AIO (a poll that waits, an eventfd signalled),
/// process accounting, dnotify, queued real-time signals, file attributes,
/// the security modules, `sync`, a trailing slash on a file,
/// `kernel.msg_next_id`, `process_vm_readv`/`writev`, Landlock, and a
/// port below 1024 on loopback addresses, which the host keeps for root.
#[test]
fn more_calls() {
    let out = fwe(&rust_guest("calls3"), &[]);
    assert_eq!(stdout(&out), CALLS3, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0));
}

/// The same in the VM (see [`more_calls`]): AIO's buffers and the ring
/// through the guest's translated memory.
#[test]
fn hv_more_calls() {
    let Some(out) = fwe_hv(&rust_low_guest("calls3"), &[]) else { return };
    assert_eq!(stdout(&out), CALLS3, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0));
}

/// What the `keys` guest prints.
const KEYS: &str = "session true, key read true, described true\n\
    child shares the session true, its key here true\n\
    request refused true, negative key true\n\
    revoked true\n\
    listed true\n\
    after exec: session key true, process keyring gone true\n";

/// Keys and keyrings: a session keyring a fork child shares and adds to,
/// a negative key from a request no helper answers, a revoked key,
/// `/proc/keys`, and the keyrings `execve` keeps and drops.
#[test]
fn keys_are_kept_across_processes() {
    let out = fwe(&rust_guest("keys"), &[]);
    assert_eq!(stdout(&out), KEYS, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0));
}

/// inotify: a watched directory hears what another process does in it,
/// in Linux's order, `poll` sees the events, fdinfo lists the watch, and a
/// removed watch reports `IN_IGNORED`.
#[test]
fn inotify_reports_another_process_s_changes() {
    let out = fwe(&rust_guest("inotify"), &[]);
    assert_eq!(stdout(&out), INOTIFY, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0));
}

/// What the `loopdev` guest prints.
const LOOPDEV: &str = "free: true\n\
    node: 0, block device: true, 7:N: true\n\
    unattached: status true, size 0, read 0\n\
    attach: 0\n\
    busy: true\n\
    size: 65536, sector size 512\n\
    sys size: 128\n\
    sys backing file: true\n\
    read: 100, the file's: true\n\
    read at the end: 84, the file's: true\n\
    set status: 0\n\
    size: 32768\n\
    read at 0: 16, the file's at the offset: true\n\
    write: 3\n\
    written to the file after the offset: true\n\
    write past the end: true\n\
    seek: end 32768, past it true\n\
    status: number true, offset 16384, limit 32768, name test\n\
    mapped: true\n\
    fork: child read true, position shared true\n\
    remove attached: true\n\
    detach: 0\n\
    detached: again true, status true, size 0\n\
    run down: held true, closed true\n\
    added: true, shown true\n\
    removed: 0, gone true\n\
    control read: true\n";

/// A loop device set up and used as a program does: a free one from
/// `/dev/loop-control`, a file attached and read, written and mapped
/// through it from an offset within a size limit, its position shared
/// with a fork child, `/sys/block` showing it, then detached (run down,
/// so another process cannot attach it, until closed); and a device added
/// and removed.
#[test]
fn loop_devices_show_a_file() {
    let out = fwe(&rust_guest("loopdev"), &[]);
    assert_eq!(stdout(&out), LOOPDEV, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0));
}

/// Run one scenario of the `memfd` guest and return its output.
fn memfd(scenario: &str) -> String {
    let out = fwe(&rust_guest("memfd"), &[scenario]);
    eprintln!("--- memfd {scenario} stderr:\n{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0), "{scenario}");
    stdout(&out)
}

/// What the `memfd` guest's `seals` scenario prints: a memfd named as
/// Linux names it, and each seal holding.
const MEMFD_SEALS: &str = "\
link: /memfd:plain (deleted)
seals: 1
sealing it: -1 EPERM
not a memfd: -1 EINVAL
sealable: 0
shrink: -1 EPERM
grow: -1 EPERM
same size: 0
write: -1 EPERM
writable mapping: -1 EPERM
read-only mapping: true
still open for writing: true
seals now: 15
more: -1 EPERM
reopened: true seals 15
";

/// A memfd's seals hold as on Linux: against resizing, writing and
/// writable shared mappings, through every descriptor of it.
#[test]
fn memfd_seals_hold() {
    assert_eq!(memfd("seals"), MEMFD_SEALS);
}

/// What the copy of the `memfd` guest run from a sealed memfd prints.
fn memfd_child(how: &str) -> String {
    format!("running {how} as copy\nexe: /memfd:self (deleted)\nexe sealed: true\n")
}

/// A program runs from a sealed memfd, as crun re-executes itself: by
/// descriptor (`execveat` with `AT_EMPTY_PATH`), by its `/proc/self/fd`
/// path, and from a process with another thread (where fwe re-executes
/// itself); `/proc/self/exe` then opens the memfd, seals and all.
#[test]
fn program_runs_from_a_sealed_memfd() {
    assert_eq!(memfd("exec"), memfd_child("by-descriptor"));
    assert_eq!(memfd("exec-path"), memfd_child("by-path"));
    assert_eq!(memfd("exec-threaded"), memfd_child("from-a-thread"));
}

/// Run one scenario of the `fds` guest from inside a root filesystem (so
/// path resolution depends on fwe's handle on it) and return its output.
fn fds(scenario: &str) -> String {
    let root = std::env::temp_dir().join(format!("fwe-fds-{}-{scenario}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::copy(rust_guest("fds"), root.join("fds")).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fwe"));
    cmd.arg("--strace").arg("--root").arg(&root).arg(root.join("fds")).arg(scenario);
    let out = run_bounded(cmd);
    eprintln!("--- fds {scenario} stderr:\n{}", String::from_utf8_lossy(&out.stderr));
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(out.status.code(), Some(0), "{scenario}");
    stdout(&out)
}

/// A guest that closes every descriptor from 3 up to its limit, as daemons
/// and spawn helpers do, leaves fwe's own descriptors (the rootfs handle,
/// the pipes behind eventfd and signalfd) untouched: paths still resolve and
/// both emulated descriptors still work.
#[test]
fn closing_every_descriptor_spares_fwes_own() {
    assert_eq!(
        fds("close-all"),
        "soft limit 1024\nread own binary: true\neventfd: 8 bytes, value 3\nsignalfd: 128 bytes, signal 10\n"
    );
}

/// `close_range(3, ~0)` closes the guest's descriptors and nothing of fwe's.
#[test]
fn close_range_closes_only_the_guests() {
    assert_eq!(fds("close-range"), "close_range 0, file closed: true\nread own binary: true\n");
}

/// `/proc/self/fd` lists exactly the guest's open descriptors; each entry
/// links to the file's guest path or names a pipe, and opening one gives a
/// working descriptor.
#[test]
fn proc_self_fd_lists_and_links_descriptors() {
    assert_eq!(
        fds("proc-fd"),
        "lists the open ones: true\nand nothing else: true\nfile link is its path: true\n\
         pipe link: true\nreopened pipe reads: 1 z\n"
    );
}

/// `RLIMIT_NOFILE` is virtual: its hard limit starts where fwe's own range
/// begins, so `dup2` there fails with `EBADF`; root may raise it as far as
/// `fs.nr_open`, not past it.
#[test]
fn descriptor_limit_bounds_the_guest() {
    assert_eq!(fds("limits"), FDS_LIMITS);
}

/// What the `fds` guest's `limits` scenario prints: the guest's soft
/// `RLIMIT_NOFILE` held as Linux holds it.
const FDS_LIMITS: &str = "\
hard limit above soft: true
dup2 at the soft limit: -1 EBADF
dup2 just below it: true
F_DUPFD from it: -1 EINVAL
raising past fs.nr_open: -1 EPERM
raising to it: 0, hard limit now fs.nr_open true
soft limit now 32
dup stopped at 32: EMFILE
eventfd: -1 EMFILE
pipe with one free: -1 EMFILE
eventfd with one free: true
and counts: 8 8 7
";

/// A bad pointer makes a system call fail with `EFAULT` instead of crashing
/// fwe: pointers the kernel layer copies through itself (`uname`, `openat`,
/// `rt_sigaction`, `getrandom`, `pipe2`, `getcwd`, `execve`, `sigaltstack`,
/// `newfstatat`, including a write into read-only code) and those the host
/// checks (`clock_gettime`, `write`).
#[test]
fn bad_pointers_fail_with_efault() {
    for name in ["efault", "efault-pie"] {
        assert_eq!(fwe(&asm_guest(name), &[]).status.code(), Some(0), "{name}");
    }
}

// --- The hypervisor backend ------------------------------------------------
//
// By default these run on the software stand-in for Hypervisor.framework
// (`fwe --hv-standin`, which needs Unicorn), with the unsigned `fwe`, which
// cannot create a real VM at all. Only with `FWE_HV_TESTS=1` do they use the
// real framework, where it works: a bare-metal Apple Silicon Mac (not
// GitHub's hosted runners, which are VMs themselves), with `fwe` copied and
// signed with the hypervisor entitlement. Where neither can run, the tests
// report that they were skipped and pass.

/// The name of a running process that uses the hypervisor itself (a VM
/// manager), if any.
fn other_hypervisor_client() -> Option<String> {
    const CLIENTS: &[&str] = &[
        "krunkit",
        "vfkit",
        "qemu-system-aarch64",
        "com.apple.Virtualization.VirtualMachine",
        "limactl",
        "UTM",
        "VirtualBoxVM",
        "prl_vm_app",
    ];
    let ps = Command::new("ps").args(["-axco", "comm="]).output().ok()?;
    String::from_utf8_lossy(&ps.stdout)
        .lines()
        .map(str::trim)
        .find(|name| CLIENTS.contains(name))
        .map(str::to_string)
}

/// How the VM tests run their programs.
enum HvMode {
    /// On the real framework, with this signed copy of `fwe`.
    Real(PathBuf),
    /// On the stand-in, with the unsigned `fwe`.
    Standin,
}

/// Where Unicorn is, for the stand-in (as `fwe` looks for it).
fn unicorn_present() -> bool {
    let named = std::env::var_os("FWE_UNICORN").map(PathBuf::from);
    named
        .into_iter()
        .chain(
            ["/opt/homebrew/lib/libunicorn.2.dylib", "/usr/local/lib/libunicorn.2.dylib"]
                .map(PathBuf::from),
        )
        .any(|p| p.exists())
}

/// How this host runs the VM tests, if it can.
fn hv_mode() -> Option<&'static HvMode> {
    static MODE: OnceLock<Option<HvMode>> = OnceLock::new();
    MODE.get_or_init(|| {
        // The real framework only on request: misusing it can bring the
        // machine down (the safety rules in docs/hypervisor.md), so a
        // plain `cargo test` never starts a VM. Only a machine whose crash
        // costs nothing (the self-hosted runner) sets this.
        if std::env::var_os("FWE_HV_TESTS").is_none_or(|v| v != "1") {
            if cfg!(all(target_os = "macos", target_arch = "aarch64")) && unicorn_present() {
                // A second guard besides the stand-in itself: this fwe must
                // be unable to create a real VM.
                let sig = Command::new("codesign")
                    .args(["-d", "--entitlements", "-", env!("CARGO_BIN_EXE_fwe")])
                    .output()
                    .unwrap();
                let sig =
                    String::from_utf8_lossy(&sig.stdout) + String::from_utf8_lossy(&sig.stderr);
                assert!(
                    !sig.contains("com.apple.security.hypervisor"),
                    "{} carries the hypervisor entitlement; the stand-in tests need one that \
                     cannot create a VM (rebuild it, or sign a copy instead)",
                    env!("CARGO_BIN_EXE_fwe")
                );
                return Some(HvMode::Standin);
            }
            eprintln!(
                "skipped: the VM tests need Unicorn for the stand-in (`brew install unicorn`), \
                 or FWE_HV_TESTS=1 for the real framework"
            );
            return None;
        }
        real_fwe().map(HvMode::Real)
    })
    .as_ref()
}

/// `fwe` signed with the hypervisor entitlement, if this host can run a VM.
fn real_fwe() -> Option<PathBuf> {
    // Never alongside another hypervisor client, such as Podman's krunkit
    // (the safety rules in docs/hypervisor.md).
    if let Some(other) = other_hypervisor_client() {
        eprintln!(
            "skipped: another hypervisor client is running ({other}); \
             stop it (for Podman: `podman machine stop`) to run the VM tests"
        );
        return None;
    }
    let support = Command::new("sysctl").args(["-n", "kern.hv_support"]).output().ok()?;
    if String::from_utf8_lossy(&support.stdout).trim() != "1" {
        return None;
    }
    let signed = out_dir().join("fwe-hv");
    std::fs::create_dir_all(out_dir()).unwrap();
    std::fs::copy(env!("CARGO_BIN_EXE_fwe"), &signed).unwrap();
    let ok = Command::new("codesign")
        .args(["--sign", "-", "--force", "--entitlements"])
        .arg(repo().join("hypervisor.entitlements"))
        .arg(&signed)
        .status()
        .is_ok_and(|s| s.success());
    // A host that has the hypervisor but refuses the VM (no
    // entitlement honoured) also counts as unavailable.
    let _one = ONE_VM.lock().unwrap_or_else(|e| e.into_inner());
    let mut spike = Command::new(&signed);
    spike.arg("--hv-spike");
    let spike = run_vm_bounded(spike);
    (ok && spike.status.success()).then_some(signed)
}

/// A command running `fwe` as the VM tests do, or `None` (test skipped)
/// when this host can run neither the stand-in nor a VM.
fn hv_command() -> Option<Command> {
    let Some(mode) = hv_mode() else {
        eprintln!("skipped: no hypervisor on this host");
        return None;
    };
    let mut cmd = match mode {
        HvMode::Real(fwe) => Command::new(fwe),
        HvMode::Standin => {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_fwe"));
            cmd.arg("--hv-standin");
            cmd
        }
    };
    // The flight recorder, for runs on real hardware (the `hypervisor` CI
    // job sets it); passed as an option, so a test that clears the
    // environment is recorded too.
    if let Some(spec) = std::env::var_os("FWE_HV_RECORD").filter(|s| !s.is_empty()) {
        cmd.arg("--hv-record").arg(spec);
    }
    Some(cmd)
}

/// Run a VM test's command: one at a time on the real framework, and
/// failing on any rule the stand-in saw broken.
fn run_hv(cmd: Command, what: &str) -> Output {
    let limit =
        if matches!(hv_mode(), Some(HvMode::Standin)) { STANDIN_TIMEOUT } else { GUEST_TIMEOUT };
    run_hv_for(cmd, what, limit)
}

/// [`run_hv`] for a workload that can fail far from its cause (a loader
/// saying only that a segment could not be mapped): `args` adds the
/// command's arguments to [`hv_command`]'s. The run is traced with
/// `--strace=failures`, which leaves its timing much as it is; the guest's
/// own standard error is echoed, and when the output is not `expected` the
/// failed memory calls and fwe's notes (why code could not be prepared,
/// say) are printed too.
fn run_hv_explained(args: impl Fn(&mut Command), what: &str, expected: &str) -> Option<Output> {
    let mut cmd = hv_command()?;
    cmd.arg("--strace=failures");
    args(&mut cmd);
    let limit =
        if matches!(hv_mode(), Some(HvMode::Standin)) { STANDIN_TIMEOUT } else { GUEST_TIMEOUT };
    let out = run_hv_quietly(cmd, what, limit);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let (trace, guest): (Vec<&str>, Vec<&str>) =
        stderr.lines().partition(|l| l.starts_with("[fwe] "));
    eprintln!("--- hv {what} stderr:\n{}", guest.join("\n"));
    if stdout(&out) != expected || !out.status.success() {
        let memory = ["mmap(", "mprotect(", "munmap(", "mremap("];
        let telling: Vec<&str> = trace
            .into_iter()
            .filter(|l| {
                let line = &l["[fwe] ".len()..];
                // A note, or a memory call that failed.
                !line.contains(") = ") || memory.iter().any(|m| line.starts_with(m))
            })
            .collect();
        eprintln!("--- {what}: failed memory calls and fwe's notes:\n{}", telling.join("\n"));
    }
    Some(out)
}

/// [`run_hv`] with a time limit of its own, for a long workload.
fn run_hv_for(cmd: Command, what: &str, limit: Duration) -> Output {
    let out = run_hv_quietly(cmd, what, limit);
    eprintln!("--- hv {what} stderr:\n{}", String::from_utf8_lossy(&out.stderr));
    out
}

/// [`run_hv_for`] without echoing the standard error, for a traced run.
fn run_hv_quietly(cmd: Command, what: &str, limit: Duration) -> Output {
    let _one = matches!(hv_mode(), Some(HvMode::Real(_)))
        .then(|| ONE_VM.lock().unwrap_or_else(|e| e.into_inner()));
    let out = run_vm_bounded_for(cmd, limit);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if let Some(line) = stderr.lines().find(|l| l.contains("fwe hv stand-in: VIOLATION")) {
        panic!("{what}: {line}");
    }
    out
}

/// The Rust guests linked at the toolchain's default (low) address, which
/// only the hypervisor backend can run.
fn rust_low_guest(name: &str) -> PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    let dir = DIR.get_or_init(|| {
        build_guests();
        let out = out_dir().join("rust-low");
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let mut build = Command::new(cargo);
        build
            .args(["build", "--release", "--manifest-path"])
            .arg(repo().join("guests/rust/Cargo.toml"))
            .arg("--target-dir")
            .arg(&out)
            .current_dir(repo().join("guests/rust"));
        for (key, _) in std::env::vars() {
            if key.starts_with("CARGO_") || key == "RUSTFLAGS" || key == "RUSTC_WRAPPER" {
                build.env_remove(key);
            }
        }
        // RUSTFLAGS replaces the config's flags, dropping its high image base.
        build.env(
            "RUSTFLAGS",
            "-C linker-flavor=ld.lld -C link-self-contained=yes -C target-feature=+crt-static \
             -C link-arg=--build-id",
        );
        run_checked(&mut build);
        out
    });
    dir.join("aarch64-unknown-linux-musl/release").join(name)
}

/// Held while one of the big workloads runs (a Debian program suite, natively
/// or in the VM), so they run one at a time: each is bounded by a time limit
/// that is meant to catch a hang, and run beside the others on a busy runner
/// they took several times as long. Taken once a test's files are fetched,
/// and before [`ONE_VM`].
static WORKLOAD: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn workload() -> std::sync::MutexGuard<'static, ()> {
    WORKLOAD.lock().unwrap_or_else(|e| e.into_inner())
}

/// Held while a VM process runs, so the tests never run more than one at a
/// time: Hypervisor.framework is shared with whatever else on the machine
/// uses it, and the tests should not stress it.
static ONE_VM: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Run `program` in the VM backend (see [`hv_command`]), or `None` (test
/// skipped) when this host cannot.
fn fwe_hv(program: &Path, args: &[&str]) -> Option<Output> {
    let mut cmd = hv_command()?;
    cmd.arg("--strace").arg(program).args(args).env("FWE_GUEST_VAR", "from-host");
    Some(run_hv(cmd, &program.display().to_string()))
}

/// Assembly guests linked below 4 GiB run in the VM: system calls, the
/// thread pointer, x18 (simply the guest's own register there), signal
/// handlers with their frames and FP state, the event descriptors, sockets,
/// /proc, credentials and bad pointers.
#[test]
fn hv_runs_low_assembly_guests() {
    let cases = [
        ("hello", 0),
        ("exit42", 42),
        ("enosys", 0),
        ("regs", 0),
        ("tpidr", 0),
        ("x18", 0),
        ("x18spin", 0),
        ("x18mem", 0),
        ("x18dp", 0),
        ("x18ldst", 0),
        ("x18br", 0),
        ("x18fp", 0),
        ("x18pc", 0),
        ("x18sig", 0),
        ("sigtest", 0),
        ("fpsig", 0),
        ("signalfdtest", 0),
        ("epolltest", 0),
        ("eventfdtest", 0),
        ("timerfdtest", 0),
        ("socketpairtest", 0),
        ("procread", 0),
        ("procdir", 0),
        ("credtest", 0),
        ("sigmap", 0),
        ("hvsys", 0),
    ];
    for (name, code) in cases {
        let low = format!("{name}-low");
        let Some(out) = fwe_hv(&asm_guest(&low), &[]) else { return };
        assert_eq!(out.status.code(), Some(code), "{low}");
    }
    let out = fwe_hv(&asm_guest("hello-low"), &[]).unwrap();
    assert_eq!(stdout(&out), "hello from linux\n");
}

/// Rust programs linked at the default low address (std's runtime, heap,
/// threads-free sleep, clock, a large allocation, arguments) run in the VM.
#[test]
fn hv_runs_low_rust_programs() {
    let Some(out) = fwe_hv(&rust_low_guest("hello"), &[]) else { return };
    assert_eq!(stdout(&out), "hello from rust on linux\n");
    let out = fwe_hv(&rust_low_guest("sysinfo"), &[]).unwrap();
    assert_eq!(
        stdout(&out),
        "heap ok: 10000 entries, 314616 bytes\nsleep ok: true\nclock ok: true\nlarge allocation ok: true\n"
    );
    let out = fwe_hv(&rust_low_guest("args"), &["one", "two words"]).unwrap();
    assert!(
        stdout(&out).ends_with("arg[1]=one\narg[2]=two words\nFWE_GUEST_VAR=from-host\n"),
        "{out:?}"
    );
    // Writable and executable memory: the VM maps it so, the host never.
    let out = fwe_hv(&rust_low_guest("signals"), &["jit"]).unwrap();
    assert_eq!(stdout(&out), JIT);
}

/// The VM's mappings as `/proc/self/maps` lists them (see
/// [`proc_maps_lists_the_mappings`]).
#[test]
fn hv_lists_the_mappings() {
    let Some(out) = fwe_hv(&rust_low_guest("maps"), &[]) else { return };
    assert_eq!(stdout(&out), MAPS, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0));
}

/// The same calls in the VM (see [`kernel_calls_move_data_and_keep_settings`]):
/// their buffers and offsets are the guest's memory, translated.
#[test]
fn hv_kernel_calls_move_data_and_keep_settings() {
    let Some(out) = fwe_hv(&rust_low_guest("calls"), &[]) else { return };
    assert_eq!(stdout(&out), CALLS, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0));
}

/// Message queues in the VM (see [`message_queues_deliver_and_notify`]):
/// the messages, attributes and notification values are the guest's
/// memory, translated, and a forking guest's processes each have a VM.
#[test]
fn hv_message_queues_deliver_and_notify() {
    let Some(out) = fwe_hv(&rust_low_guest("mqueue"), &[]) else { return };
    assert_eq!(stdout(&out), MQUEUE, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0));
}

/// Process descriptors in the VM (see
/// [`process_descriptors_name_processes`]).
#[test]
fn hv_process_descriptors_name_processes() {
    let Some(out) = fwe_hv(&rust_low_guest("pidfd"), &[]) else { return };
    assert_eq!(stdout(&out), PIDFD, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0));
}

/// ptrace in the VM (see [`ptrace_traces_a_child`]): a fork child is a
/// fresh process that learns from its snapshot to be traced, and code a
/// tracer writes is fetched afresh.
#[test]
fn hv_ptrace_traces_a_child() {
    let Some(out) = fwe_hv(&rust_low_guest("ptrace"), &[]) else { return };
    assert_eq!(stdout(&out), PTRACE, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0));
}

/// What debuggers ask of ptrace, in the VM (see [`ptrace_serves_debuggers`]).
#[test]
fn hv_ptrace_serves_debuggers() {
    let Some(out) = fwe_hv(&rust_low_guest("debugger"), &[]) else { return };
    assert_eq!(stdout(&out), DEBUGGER, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0));
}

/// Robust mutexes in the VM (see [`robust_mutexes_report_a_dead_owner`]):
/// the futex words are released through the guest's translated memory.
#[test]
fn hv_robust_mutexes_report_a_dead_owner() {
    let Some(out) = fwe_hv(&rust_low_guest("robust"), &[]) else { return };
    assert_eq!(stdout(&out), ROBUST, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0));
}

/// The new mount API in the VM (see
/// [`the_new_mount_api_makes_and_attaches_mounts`]): its structures are
/// the guest's memory, translated.
#[test]
fn hv_the_new_mount_api_makes_and_attaches_mounts() {
    let Some(out) = fwe_hv(&rust_low_guest("mountapi"), &[]) else { return };
    assert_eq!(stdout(&out), MOUNTAPI, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0));
}

/// Namespace descriptors in the VM (see
/// [`namespace_descriptors_name_and_join_namespaces`]).
#[test]
fn hv_namespace_descriptors_name_and_join_namespaces() {
    let Some(out) = fwe_hv(&rust_low_guest("nsfd"), &[]) else { return };
    assert_eq!(stdout(&out), NSFD, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0));
}

/// Keys in the VM (see [`keys_are_kept_across_processes`]): payloads and
/// descriptions copied through guest memory, a forking and re-executing
/// guest.
#[test]
fn hv_keys_are_kept_across_processes() {
    let Some(out) = fwe_hv(&rust_low_guest("keys"), &[]) else { return };
    assert_eq!(stdout(&out), KEYS, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0));
}

/// inotify in the VM (see [`inotify_reports_another_process_s_changes`]):
/// a forking guest, its events read into guest memory, translated.
#[test]
fn hv_inotify_reports_another_process_s_changes() {
    let Some(out) = fwe_hv(&rust_low_guest("inotify"), &[]) else { return };
    assert_eq!(stdout(&out), INOTIFY, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0));
}

/// A loop device in the VM (see [`loop_devices_show_a_file`]): its
/// mapping is of the attached file.
#[test]
fn hv_loop_devices_show_a_file() {
    let Some(out) = fwe_hv(&rust_low_guest("loopdev"), &[]) else { return };
    assert_eq!(stdout(&out), LOOPDEV, "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.status.code(), Some(0));
}

/// Signals in the VM: handlers for timers, real-time and sent fault signals,
/// sigtimedwait, default SIGPIPE, and a timer that interrupts a guest
/// computing without system calls (the backend stops the vCPU).
#[test]
fn hv_delivers_signals() {
    let run = |scenario: &str| fwe_hv(&rust_low_guest("signals"), &[scenario]);
    let Some(out) = run("busy-alarm") else { return };
    assert_eq!(stdout(&out), "busy loop interrupted: true\n");
    for (scenario, want) in [
        ("pause", "pause: -1 errno 4, handler ran: true\n"),
        ("rt-self", "handled: 1, signal 40\n"),
        ("sigtimedwait", "took 12, code 0\nthen -1 errno EAGAIN\n"),
        ("notify-parent-blocked", "SIGUSR1 from child: true\nexited 0\n"),
        ("sigwait-from-child", "took 12 from child: true\nexited 0\n"),
        ("tgkill-blocked", "held for the blocking thread: true, then handled on it: true\n"),
        ("default-blocked", "still running, pending: true\n"),
        ("stop-tstp", "stopped: true, by 20\nkilled by 9\n"),
        (
            "raise-faults",
            "signal 11: handled 1\nsignal 8: handled 1\nsignal 5: handled 1\nignored SIGTRAP: still running\n",
        ),
    ] {
        let out = run(scenario).unwrap();
        assert_eq!(stdout(&out), want, "{scenario}");
    }
    use std::os::unix::process::ExitStatusExt;
    let out = run("sigpipe").unwrap();
    assert_eq!(out.status.signal(), Some(libc::SIGPIPE));
}

/// A child in a new user namespace, made by a raw `clone` from a second
/// thread (as Go makes one), sets its parent-death signal, asks for its
/// parent and ends: natively and in the VM, whose fork child starts from
/// the snapshot the cloning thread's registers are in.
#[test]
fn userns_clone_from_a_thread() {
    let want = "child's parent ours: true, its namespace seen: true, killed by 9\n";
    assert_eq!(namespaces("userns-thread-clone"), want);
    let Some(out) = fwe_hv(&rust_low_guest("namespaces"), &["userns-thread-clone"]) else { return };
    assert_eq!(stdout(&out), want);
    // Killed as soon as it is made, before it has run.
    let out = fwe_hv(&rust_low_guest("namespaces"), &["kill-at-once"]).unwrap();
    assert_eq!(stdout(&out), "killed at once: 20 of 20\n");
}

/// Namespaces in the VM, whose fork child starts from a snapshot of the
/// namespaces made for it: a pid namespace numbering from 1, a UTS
/// namespace's own name, a user namespace's maps.
#[test]
fn hv_namespaces() {
    let run = |scenario: &str| fwe_hv(&rust_low_guest("namespaces"), &[scenario]);
    let Some(out) = run("pid") else { return };
    assert_eq!(
        stdout(&out),
        "child: pid 1 ppid 0\ngrandchild: pid 2 ppid 1\nforked 2\nkill: 0\n\
         reaped 2, killed by 9\nno such pid: -1 errno 3\n\
         parent: child true reaped as itself, exited 7\n"
    );
    let out = run("uts").unwrap();
    assert!(
        stdout(&out)
            .starts_with("inside: box\nproc: box\nchild exited 0, outside unchanged: true\n"),
        "{}",
        stdout(&out)
    );
    let out = run("user").unwrap();
    assert!(
        stdout(&out).ends_with("parent wrote the map: true\nin child: uid 0, setuid(5) 0, uid 5\n"),
        "{}",
        stdout(&out)
    );
}

/// memfds in the VM: seals hold, and a program runs from a sealed memfd,
/// which the VM process hands to the fwe it re-executes by descriptor.
#[test]
fn hv_runs_a_program_from_a_sealed_memfd() {
    let run = |scenario: &str| fwe_hv(&rust_low_guest("memfd"), &[scenario]);
    let Some(out) = run("seals") else { return };
    assert_eq!(stdout(&out), MEMFD_SEALS);
    for (scenario, how) in [("exec", "by-descriptor"), ("exec-path", "by-path")] {
        let out = run(scenario).unwrap();
        assert_eq!(stdout(&out), memfd_child(how), "{scenario}");
    }
}

/// The kernel's view of guest memory in the VM: /proc/self/fd and the
/// descriptor limit, and pointers into the translated image (static
/// buffers) passed to the host.
#[test]
fn hv_descriptors_and_translated_pointers() {
    let Some(out) = fwe_hv(&rust_low_guest("fds"), &["proc-fd"]) else { return };
    assert_eq!(
        stdout(&out),
        "lists the open ones: true\nand nothing else: true\nfile link is its path: true\n\
         pipe link: true\nreopened pipe reads: 1 z\n"
    );
    let out = fwe_hv(&rust_low_guest("fds"), &["limits"]).unwrap();
    assert_eq!(stdout(&out), FDS_LIMITS);
}

/// A dynamically linked, non-PIE glibc program at a low address — the shape
/// of Debian's `python3.11` — runs in the VM: the image at its link address
/// (translated), glibc's dynamic linker and `libc.so.6` mapped by the guest
/// at the same addresses as in the host, relocations and RELRO applied by
/// the guest's own `ld.so`.
#[test]
fn hv_runs_dynamic_non_pie_glibc_program() {
    let prog = build_c("dynhello", Libc::Glibc, true, false);
    let root = libc_rootfs(Libc::Glibc, "glibc-nopie");
    let Some(out) = fwe_hv_in(&root, &prog, &["fun-with-emulators"]) else { return };
    assert_eq!(stdout(&out), "dynamic hello, fun-with-emulators\n");
    assert_eq!(out.status.code(), Some(0));
    let _ = std::fs::remove_dir_all(&root);
}

/// [`fwe_hv`] with a root filesystem.
fn fwe_hv_in(root: &Path, program: &Path, args: &[&str]) -> Option<Output> {
    let mut cmd = hv_command()?;
    cmd.arg("--strace").arg("--root").arg(root).arg(program).args(args);
    Some(run_hv(cmd, &program.display().to_string()))
}

/// Debian's Python 3.11 (fetched: `guests/debian/fetch/python.txt`), a
/// non-PIE executable linked at `0x400000`, so the VM runs it: the standard
/// library's C modules (sqlite3, hashlib on OpenSSL, zlib, bz2, lzma,
/// decimal, unicodedata), threads, a socket pair, an asyncio server and
/// client, ctypes calling into libc and libffi's closures called back, a
/// signal handler, `fork`, a shell run by `subprocess` (the native backend,
/// by `execve`), and a process pool, whose locks are POSIX semaphores in
/// `/dev/shm` shared by the processes.
#[test]
fn hv_debian_python_runs_a_workload() {
    let root = fetched_root("python");
    let _workload = workload();
    let script = format!("/tmp/fwe-python-{}.py", std::process::id());
    std::fs::write(root.join(script.trim_start_matches('/')), PYTHON_WORKLOAD).unwrap();
    let Some(mut cmd) = hv_command() else { return };
    cmd.arg("--root")
        .arg(&root)
        .arg(root.join("usr/bin/python3.11"))
        .arg("-B")
        .arg(&script)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/tmp")
        .stdin(Stdio::null());
    let out = run_hv(cmd, "python3.11");
    let _ = std::fs::remove_file(root.join(script.trim_start_matches('/')));
    assert_eq!(
        stdout(&out),
        "executable /usr/bin/python3.11\n\
         json {\"a\": [1, 2, {\"b\": null}]}\n\
         re host at user and there at me\n\
         sqlite (100, 4950, '9801')\n\
         sha256 9c3ef3144c6828d97a4c2d6a1e7d07ba9f68b8ba2354dfa1f0717fb29023c10b\n\
         compress 6000 6000 6000\n\
         threads 4 418819\n\
         socket b'ping'\n\
         asyncio b'ASYNCIO ECHO\\n'\n\
         decimal 0.1428571428571428571428571428571428571429\n\
         ctypes 12 [1, 2, 3, 4, 5]\n\
         signal [10]\n\
         unicode LATIN SMALL LETTER E WITH ACUTE STRASSE\n\
         fork 7\n\
         subprocess from-sh 42\n\
         processes [1024, 59049, 1048576]\n\
         shm True\n"
    );
    assert_eq!(out.status.code(), Some(0));
}

/// Debian's GCC 12 (fetched: `guests/debian/fetch/gcc.txt`), whose driver,
/// `cc1` and `collect2` are non-PIE executables the VM runs, while GNU `as`
/// and `ld` run natively: a program with a thread and libm compiled and
/// linked, and one built from a static library made with `ar`, linked as a
/// PIE (run natively), a non-PIE and a static executable (both run in the
/// VM). A shell script drives it, so every compiler stage is an `execve`
/// between the backends.
#[test]
fn hv_debian_gcc_builds_c_programs() {
    let root = fetched_root("gcc");
    let _workload = workload();
    let proj = format!("tmp/fwe-gcc-{}", std::process::id());
    let dir = root.join(&proj);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let files = [
        (
            "hello.c",
            r#"#include <math.h>
#include <pthread.h>
#include <stdio.h>
static void *work(void *arg) {
    long n = (long)arg, s = 0;
    for (long i = 0; i < n; i++) s += i;
    return (void *)s;
}
int main(int argc, char **argv) {
    pthread_t t;
    void *r;
    pthread_create(&t, 0, work, (void *)1000);
    pthread_join(t, &r);
    printf("hello from gcc: %s %ld %.4f\n", argc > 1 ? argv[1] : "-", (long)r, sqrt(2.0));
    return 0;
}
"#,
        ),
        ("util.c", "int triple(int x) { return 3 * x; }\n"),
        (
            "main.c",
            "#include <stdio.h>\nint triple(int);\n\
             int main(void) { printf(\"triple %d\\n\", triple(14)); return 0; }\n",
        ),
        (
            "build.sh",
            "set -e\n\
             cc=aarch64-linux-gnu-gcc-12\n\
             $cc -O2 -Wall -o hello hello.c -lm\n\
             ./hello world\n\
             $cc -c -O2 util.c\n\
             ar rcs libutil.a util.o\n\
             $cc -O2 -o pie main.c -L. -lutil\n\
             $cc -O2 -no-pie -o nopie main.c -L. -lutil\n\
             $cc -O2 -static -o static main.c -L. -lutil\n\
             ./pie\n./nopie\n./static\n",
        ),
    ];
    for (name, text) in files {
        std::fs::write(dir.join(name), text).unwrap();
    }
    let expected = "hello from gcc: world 499500 1.4142\ntriple 42\ntriple 42\ntriple 42\n";
    let args = |cmd: &mut Command| {
        cmd.arg("--root")
            .arg(&root)
            .arg("--cwd")
            .arg(format!("/{proj}"))
            .arg(root.join("bin/bash"))
            .arg("build.sh")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null());
    };
    let Some(out) = run_hv_explained(args, "gcc", expected) else { return };
    assert_eq!(stdout(&out), expected);
    assert_eq!(out.status.code(), Some(0));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Debian's clang 14 (fetched: `guests/debian/fetch/clang.txt`), a non-PIE
/// executable the VM runs, with LLVM's libraries, GNU `ld` linking
/// natively: a C program using libm and a C++ one using the standard
/// library (libstdc++), each compiled, linked and run.
#[test]
fn hv_debian_clang_builds_c_and_cpp() {
    let root = fetched_root("clang");
    let _workload = workload();
    let proj = format!("tmp/fwe-clang-{}", std::process::id());
    let dir = root.join(&proj);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("a.c"),
        "#include <math.h>\n#include <stdio.h>\n\
         int main(void) { printf(\"clang %.3f\\n\", sqrt(2.0)); return 0; }\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("b.cpp"),
        "#include <iostream>\n#include <numeric>\n#include <vector>\n\
         int main() { std::vector<int> v{1, 2, 3};\n\
         std::cout << \"c++ \" << std::accumulate(v.begin(), v.end(), 0) << \"\\n\"; }\n",
    )
    .unwrap();
    let expected = "clang 1.414\nc++ 6\n";
    let args = |cmd: &mut Command| {
        cmd.arg("--root")
            .arg(&root)
            .arg("--cwd")
            .arg(format!("/{proj}"))
            .arg(root.join("bin/bash"))
            .args(["-c", "set -e; clang -O2 -o a a.c -lm; ./a; clang++ -O2 -o b b.cpp; ./b"])
            .env_clear()
            .env("PATH", "/usr/lib/llvm-14/bin:/usr/bin:/bin")
            .stdin(Stdio::null());
    };
    let Some(out) = run_hv_explained(args, "clang", expected) else { return };
    assert_eq!(stdout(&out), expected);
    assert_eq!(out.status.code(), Some(0));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Debian's Go 1.19 (fetched: `guests/debian/fetch/go.txt`): the `go`
/// command and its `compile` and `link` tools, all executables linked low
/// that the VM runs, build a module (goroutines, `crypto/sha256`) and run
/// it (a static executable, in the VM too), then build and run its tests.
/// The `go` command starts its tools with `vfork`, mapping many files
/// meanwhile, and the linker preallocates its output with `fallocate`.
#[test]
fn hv_debian_go_builds_and_tests_a_module() {
    let root = fetched_root("go");
    let _workload = workload();
    let proj = format!("tmp/fwe-go-{}", std::process::id());
    let dir = root.join(&proj);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let files = [
        ("go.mod", "module example.com/hello\n\ngo 1.19\n"),
        (
            "main.go",
            r#"package main

import (
	"crypto/sha256"
	"fmt"
	"sync"
)

func sums() []int {
	var wg sync.WaitGroup
	s := make([]int, 8)
	for i := range s {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 100000; j++ {
				s[i] += j % (i + 1)
			}
		}(i)
	}
	wg.Wait()
	return s
}

func main() {
	fmt.Printf("hello from go %v %x\n", sums(), sha256.Sum256([]byte("fun-with-emulators")))
}
"#,
        ),
        (
            "main_test.go",
            r#"package main

import "testing"

func TestSums(t *testing.T) {
	if s := sums(); s[1] != 50000 {
		t.Fatalf("got %v", s)
	}
}
"#,
        ),
        ("build.sh", "set -e\ngo build -o hello .\n./hello\ngo test -count=1 .\n"),
    ];
    for (name, text) in files {
        std::fs::write(dir.join(name), text).unwrap();
    }
    let Some(mut cmd) = hv_command() else { return };
    cmd.arg("--root")
        .arg(&root)
        .arg("--cwd")
        .arg(format!("/{proj}"))
        .arg(root.join("bin/bash"))
        .arg("build.sh")
        .env_clear()
        .env("PATH", "/usr/lib/go-1.19/bin:/usr/bin:/bin")
        .env("HOME", format!("/{proj}"))
        .env("GOCACHE", format!("/{proj}/cache"))
        .env("GOPROXY", "off")
        .env("CGO_ENABLED", "0")
        .stdin(Stdio::null());
    // The stand-in on a loaded CI runner takes up to twice as long.
    let out = run_hv_for(cmd, "go", Duration::from_secs(1800));
    let text = stdout(&out);
    assert_eq!(
        text.lines().next(),
        Some(
            "hello from go [0 50000 99999 150000 200000 249996 299995 350000] \
             9c3ef3144c6828d97a4c2d6a1e7d07ba9f68b8ba2354dfa1f0717fb29023c10b"
        ),
        "{text}"
    );
    assert!(
        text.lines().nth(1).is_some_and(|l| l.starts_with("ok  \texample.com/hello\t")),
        "{text}"
    );
    assert_eq!(out.status.code(), Some(0));
    let _ = std::fs::remove_dir_all(&dir);
}

/// The script [`hv_debian_python_runs_a_workload`] runs.
const PYTHON_WORKLOAD: &str = r#"
import asyncio, bz2, concurrent.futures, ctypes, decimal, hashlib, json, lzma, os
import re, signal, socket, sqlite3, subprocess, sys, threading, unicodedata, zlib
print("executable", sys.executable)
print("json", json.dumps({"a": [1, 2, {"b": None}]}))
print("re", re.sub(r"(\w+)@(\w+)", r"\2 at \1", "user@host and me@there"))
db = sqlite3.connect(":memory:")
db.execute("create table t(x integer, y text)")
db.executemany("insert into t values (?, ?)", [(i, str(i * i)) for i in range(100)])
print("sqlite", db.execute("select count(*), sum(x), max(y) from t").fetchone())
print("sha256", hashlib.sha256(b"fun-with-emulators").hexdigest())
data = b"hello " * 1000
print("compress", len(zlib.decompress(zlib.compress(data))),
      len(bz2.decompress(bz2.compress(data))), len(lzma.decompress(lzma.compress(data))))
total, lock = [], threading.Lock()
def work(n):
    s = sum(i * i for i in range(n))
    with lock:
        total.append(s)
ts = [threading.Thread(target=work, args=(10000 + i,)) for i in range(4)]
for t in ts: t.start()
for t in ts: t.join()
print("threads", len(total), sum(total) % 1000003)
a, b = socket.socketpair()
a.sendall(b"ping")
print("socket", b.recv(4))
async def echo():
    async def handle(r, w):
        w.write((await r.readline()).upper())
        await w.drain()
        w.close()
    srv = await asyncio.start_server(handle, "127.0.0.1", 0)
    r, w = await asyncio.open_connection("127.0.0.1", srv.sockets[0].getsockname()[1])
    w.write(b"asyncio echo\n")
    await w.drain()
    line = await r.readline()
    w.close()
    srv.close()
    await srv.wait_closed()
    return line
print("asyncio", asyncio.run(echo()))
decimal.getcontext().prec = 40
print("decimal", decimal.Decimal(1) / decimal.Decimal(7))
libc = ctypes.CDLL("libc.so.6")
CMP = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int))
arr = (ctypes.c_int * 5)(5, 3, 1, 4, 2)
libc.qsort(arr, 5, ctypes.sizeof(ctypes.c_int), CMP(lambda x, y: x[0] - y[0]))
print("ctypes", libc.strlen(b"twelve chars"), list(arr))
got = []
signal.signal(signal.SIGUSR1, lambda s, f: got.append(s))
os.kill(os.getpid(), signal.SIGUSR1)
print("signal", got)
print("unicode", unicodedata.name("é"), "straße".upper())
pid = os.fork()
if pid == 0:
    os._exit(7)
print("fork", os.waitpid(pid, 0)[1] >> 8)
sh = subprocess.run(["/bin/sh", "-c", "echo from-sh $((6*7))"], capture_output=True, text=True)
print("subprocess", sh.stdout.strip())
with concurrent.futures.ProcessPoolExecutor(2) as ex:
    print("processes", list(ex.map(pow, [2, 3, 4], [10, 10, 10])))
print("shm", os.path.isdir("/dev/shm"))
"#;

/// Pointer authentication and BTI in the VM, as Linux gives them to a
/// program: keys of its own (kept by a fork child, changed by
/// `PR_PAC_RESET_KEYS`), its code mapped guarded when it is built for BTI,
/// and SIGILL for an indirect branch to no landing pad. The stand-in's CPU
/// offers both; on a real VM a feature it lacks is reported as such.
#[test]
fn hv_pointer_authentication_and_bti() {
    let Some(out) = fwe_hv(&asm_guest("pacbti-low"), &[]) else { return };
    let text = stdout(&out);
    let pac = "pac: a signed pointer authenticates\n\
               pac: a fork child has its parent's keys\n\
               pac: new keys sign differently\n";
    let bti = "bti: a branch to a landing pad goes on\n\
               bti: a branch to no landing pad raises SIGILL\n";
    if matches!(hv_mode(), Some(HvMode::Standin)) {
        assert_eq!(text, format!("{pac}{bti}"));
    } else {
        let pac_ok = text.starts_with(pac) || text.starts_with("pac: not offered\n");
        let bti_ok = text.ends_with(bti) || text.ends_with("bti: not offered\n");
        assert!(pac_ok && bti_ok, "{text}");
    }
    assert_eq!(out.status.code(), Some(0), "{text}");
}

/// MAP_FIXED over mapped memory replaces it, keeping the rest; a buffer
/// across old and new is one buffer to the kernel; a widened page takes a
/// write; a mapping over the program's own data (linked low, backed
/// elsewhere in the VM) reads as zero and takes writes.
#[test]
fn hv_map_fixed_replaces_mapped_memory() {
    let Some(out) = fwe_hv(&asm_guest("mapfixed-low"), &[]) else { return };
    let text = stdout(&out);
    let want = format!(
        "{}{}\nmap_fixed: replaces, and a buffer across both is one\n\
         mprotect: a widened page takes the write\n\
         map_fixed: over the program's own data\n",
        "A".repeat(4096),
        "B".repeat(4096)
    );
    assert_eq!(text, want);
    assert_eq!(out.status.code(), Some(0));
    // The same with another thread running guest code meanwhile.
    let out = fwe_hv(&asm_guest("mapfixedmt-low"), &[]).unwrap();
    assert_eq!(stdout(&out), "ok\n");
    assert_eq!(out.status.code(), Some(0));
}

/// The stand-in's watcher reports a process that ended with its VM alive,
/// and stays quiet about one that destroyed it first.
#[test]
fn hv_standin_watcher_reports_a_vm_left_alive() {
    if !matches!(hv_mode(), Some(HvMode::Standin)) {
        return;
    }
    for (life, reported) in [(&b"C"[..], true), (b"CD", false), (b"", false)] {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_fwe"));
        cmd.args(["--hv-standin-watch", "4242"]).stdin(Stdio::null());
        let out = run_bounded_with_stdin(cmd, life);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            stderr.contains("VIOLATION: process 4242 ended or exec'd with its VM alive"),
            reported,
            "{life:?}: {stderr}"
        );
    }
}

/// The flight recorder follows a VM process and the vfork child it starts
/// through the child's `execve`: every framework call that changes a VM is
/// recorded before and after, and each process's start and end.
#[test]
fn hv_records_the_vm_calls() {
    let Some(mut cmd) = hv_command() else { return };
    let log = out_dir().join(format!("hv-record-{}.log", std::process::id()));
    let _ = std::fs::remove_file(&log);
    cmd.arg("--hv-record").arg(format!("file:{}", log.display()));
    cmd.arg(rust_low_guest("signals")).arg("spawn-status");
    let out = run_hv(cmd, "recorded spawn-status");
    assert_eq!(stdout(&out), "hello from the spawned child\nchild exit status: 0\n");
    let record = std::fs::read_to_string(&log).unwrap();
    let _ = std::fs::remove_file(&log);
    let lines: Vec<&str> = record.lines().collect();
    assert!(lines.iter().all(|l| l.starts_with("fwe-hv ")), "{record}");
    let what = |l: &&str| l.splitn(7, ' ').nth(6).unwrap_or("").to_string();
    let pid = |l: &&str| l.split(' ').nth(3).unwrap_or("").to_string();
    let parent = pid(&lines[0]);
    let has = |p: &str, w: &str| lines.iter().any(|l| pid(l) == p && what(l).starts_with(w));
    assert!(has(&parent, "start "), "{record}");
    let child = lines
        .iter()
        .find_map(|l| what(l).strip_prefix("vfork child ").map(str::to_string))
        .expect("the vfork child is recorded");
    for p in [&parent, &child] {
        for w in
            ["> hv_vm_create", "< hv_vm_create = 0x0", "> hv_vm_destroy", "< hv_vm_destroy = 0x0"]
        {
            assert!(has(p, w), "{p}: {w}\n{record}");
        }
    }
    assert!(has(&child, "fork child starts"), "{record}");
    assert!(has(&child, "execve "), "{record}");
    assert!(has(&parent, "exit 0"), "{record}");
    // A guest that closes every descriptor it can leaves the record's
    // alone: they are fwe's, out of its reach.
    let mut cmd = hv_command().unwrap();
    cmd.arg("--hv-record").arg(format!("file:{}", log.display()));
    cmd.arg(rust_low_guest("fds")).arg("close-all-hard");
    let out = run_hv(cmd, "recorded close-all-hard");
    assert_eq!(out.status.code(), Some(0));
    let closer = std::fs::read_to_string(&log).unwrap();
    let _ = std::fs::remove_file(&log);
    assert!(closer.contains("< hv_vm_destroy = 0x0"), "{closer}");
    assert!(closer.lines().last().is_some_and(|l| l.ends_with(" exit 0")), "{closer}");
    // Every call recorded as begun is recorded as ended, in each process.
    for p in [&parent, &child] {
        let begun = lines.iter().filter(|l| pid(l) == *p && what(l).starts_with("> ")).count();
        let ended = lines.iter().filter(|l| pid(l) == *p && what(l).starts_with("< ")).count();
        assert_eq!(begun, ended, "{p}\n{record}");
    }
}

/// A program with hundreds of file mappings, which fwe's VM backend each
/// keeps a descriptor for: they stay out of the program's reach (a `vfork`
/// child taking over descriptors 3-399 still reaches its parent's memory),
/// and a shared mapping of a file opened read-only follows the file and
/// cannot be made writable.
#[test]
fn hv_many_file_mappings() {
    let prog = build_c("manymaps", Libc::Glibc, true, false);
    let root = libc_rootfs(Libc::Glibc, "glibc-manymaps-nopie");
    std::fs::create_dir_all(root.join("tmp")).unwrap();
    let Some(out) = fwe_hv_in(&root, &prog, &[]) else { return };
    assert_eq!(
        stdout(&out),
        "300 read-only shared mappings; a later write seen: 1 1\n\
         made writable: -1, errno 13\n\
         vfork child after taking descriptors 3-399: exit 10\n"
    );
    assert_eq!(out.status.code(), Some(0));
    let _ = std::fs::remove_dir_all(&root);
}

/// What `fwe --probe hv-map-rules` says on the stand-in: its inferred rule
/// for the host memory `hv_vm_map` takes. The self-hosted `hypervisor` CI
/// job compares the real framework's answers with these.
const STANDIN_MAP_RULES: &str = "\
RW, at most RWX, as RWX: mapped
RW, at most RWX, as R: mapped
R, at most RWX, as RX: mapped
R, at most RW, as RX: mapped
RW, at most RW, as RWX: mapped
R, at most R, as RX: refused
R, at most R, as R: refused
RX, at most RX, as RX: refused
shared entry of read-only memory, as RX: refused
a read-only file, shared, as RX: refused
a read-only file, private, as RX: mapped
unmapped, as R: refused
";

#[test]
fn hv_standin_map_rules() {
    if !matches!(hv_mode(), Some(HvMode::Standin)) {
        return;
    }
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fwe"));
    cmd.args(["--hv-standin", "--probe", "hv-map-rules"]);
    let out = run_hv(cmd, "hv-map-rules");
    assert_eq!(stdout(&out), STANDIN_MAP_RULES);
}

/// A signal blocked while its handler runs is delivered as soon as the
/// handler returns, even to a program that then makes no system calls; and
/// MAP_FIXED over the program's own .bss works.
#[test]
fn signal_unblocked_by_sigreturn_and_fixed_mapping() {
    for name in ["sigmap", "sigmap-pie"] {
        assert_eq!(fwe(&asm_guest(name), &[]).status.code(), Some(0), "{name}");
    }
}

/// Threads in the VM, each on a vCPU of its own: creation and join,
/// per-thread signal masks, `tgkill` to one thread (a host signal and a
/// real-time one), and a timer interrupting one thread's blocking read.
#[test]
fn hv_runs_threads() {
    for name in ["threadtest-low", "pipethread-low", "clone3test-low"] {
        let Some(out) = fwe_hv(&asm_guest(name), &[]) else { return };
        assert_eq!(out.status.code(), Some(0), "{name}");
    }
    for (scenario, want) in [
        ("thread-mask", "handled on the unblocked thread: true\n"),
        (
            "tgkill",
            "signal 12: reader EINTR, handled on it: true\nsignal 40: reader EINTR, handled on it: true\n",
        ),
        ("restart", "read: 1 byte, handler ran 1 time(s)\n"),
    ] {
        let out = fwe_hv(&rust_low_guest("signals"), &[scenario]).unwrap();
        assert_eq!(stdout(&out), want, "{scenario}");
    }
}

/// `execve` re-executes fwe, which picks the backend the new program needs:
/// from the VM to the VM (a low program execs itself), from the VM to the
/// native backend (with close-on-exec honoured), and from the native backend
/// to the VM (real bash runs a low-linked program, from another directory).
#[test]
fn hv_execve_between_backends() {
    let Some(out) = fwe_hv(&rust_low_guest("signals"), &["exec-self"]) else { return };
    assert_eq!(stdout(&out), "hello from the spawned child\n");

    let root = std::env::temp_dir().join(format!("fwe-hv-exec-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    std::fs::copy(asm_guest("execee"), root.join("execee")).unwrap();
    let out = fwe_hv_in(&root, &asm_guest("execer-low"), &[]).unwrap();
    assert_eq!(stdout(&out), "exec target ran\n");
    let _ = std::fs::remove_dir_all(&root);

    let root = debian_root();
    std::fs::copy(asm_guest("hello-low"), root.join("hello-low")).unwrap();
    let mut cmd = hv_command().unwrap();
    cmd.arg("--strace")
        .arg("--root")
        .arg(root)
        .arg(debian_bin("bash"))
        .args(["-c", "cd /lib && /hello-low; echo status=$? cwd=$PWD"])
        .env_clear()
        .env("LD_LIBRARY_PATH", "/lib")
        .env("PATH", "/bin");
    let out = run_hv(cmd, "bash -> vm");
    assert_eq!(stdout(&out), "hello from linux\nstatus=0 cwd=/lib\n");
}

/// `fork` and `vfork` in the VM: the child is a fresh fwe process with a VM
/// of its own, given the parent's memory copy-on-write and its state. The
/// fork scenarios the native backend passes pass here too: fork and wait,
/// signals between parent and child, a fork from a threaded process,
/// resource usage, `posix_spawn` and `vfork` with `execve`, copy-on-write
/// isolation, a snapshot taken at one instant while another thread writes,
/// inherited `epoll` and `timerfd` descriptors, `waitid`, whose child the
/// guest ends with `SIGKILL` (relayed, so the child's VM is torn down before
/// it dies; see docs/hypervisor.md), and a `vfork` child sharing its
/// parent's memory.
#[test]
fn hv_fork_and_vfork() {
    let Some(out) = fwe_hv(&asm_guest("forktest-low"), &[]) else { return };
    assert_eq!(out.status.code(), Some(7));
    for (scenario, want) in [
        ("kill-child", "killed by 15\n"),
        ("notify-parent", "SIGUSR1 from child: true\nexited 0\n"),
        ("sigchld", "SIGCHLD from child: true, status 3\nexited 3\n"),
        ("threaded-fork", "child of a threaded parent\nexited 5\n"),
        (
            "rusage",
            "child used cpu: true\nchild maxrss plausible: true\nown maxrss plausible: true\n",
        ),
        ("spawn", "child said: hello from the spawned child\nchild exit status: 0\n"),
        ("spawn-status", "hello from the spawned child\nchild exit status: 0\n"),
        ("vfork-exec", "hello from the spawned child\nexited 0\n"),
        (
            "fork-cow",
            "child sees the fork-time memory: true\nparent's later writes unseen: true\n\
             child's writes unseen: true\nshared memory shared: true\nexited 0\n",
        ),
        ("fork-epoll", "child's epoll: 1 event(s), data 42\nchild's timer fired: true\nexited 0\n"),
        ("fork-timerfd", FORK_TIMERFD),
        ("fork-snapshot", "consistent snapshots: 8 of 8\n"),
        ("waitid", "exited: true, status 6, pid matches: true\nkilled: true, signal 9\n"),
        ("fork-pipe", "child read 5 bytes, then the end\nexited 0\n"),
    ] {
        let out = fwe_hv(&rust_low_guest("signals"), &[scenario]).unwrap();
        assert_eq!(stdout(&out), want, "{scenario}");
        assert_eq!(out.status.code(), Some(0), "{scenario}");
    }
    let prog = build_c("dynspawn", Libc::Glibc, true, false);
    let root = libc_rootfs(Libc::Glibc, "glibc-spawn-nopie");
    let out = fwe_hv_in(&root, &prog, &[]).unwrap();
    assert_eq!(stdout(&out), VFORK_SHARES);
    assert_eq!(out.status.code(), Some(0));
    let _ = std::fs::remove_dir_all(&root);
}

/// Children made with `CLONE_PARENT` are the creator's parent's: it is
/// told when each ends and reaps each, though it is no subreaper and they
/// are not its children on the host (runc makes a container's init so, in
/// new namespaces, two levels down).
#[test]
fn clone_parent_children_are_their_parents() {
    assert_eq!(
        namespaces("fosters"),
        "then: ECHILD true\nreaped: 3 children, first true, second true, init exited 7\n\
         init's SIGCHLD: true\n"
    );
}

/// A child subreaper adopts the orphans below it: it is their parent, it
/// is sent `SIGCHLD` when one ends, and it reaps it, also one killed
/// outright; a child of its own is not a subreaper.
#[test]
fn subreaper_adopts_orphans() {
    assert_eq!(
        namespaces("subreaper"),
        "subreaper: 1\nchild exited 0\nchild is not a subreaper: true\n\
         orphan's parent is the subreaper: true\nreaped the orphan: true, exited 7\n\
         SIGCHLD from the orphan: true\nthen: -1 errno true\n"
    );
    assert_eq!(
        namespaces("subreaper-kill"),
        "child exited 0\nchild is not a subreaper: true\nproc shows the subreaper: true\n\
         not ended yet: true\nreaped the orphan: true, killed by 9\n"
    );
    // Its SIGCHLD reaches the thread that takes it, while the main thread,
    // also waiting, blocks it.
    assert_eq!(
        namespaces("subreaper-thread"),
        "child exited 0\nchild is not a subreaper: true\norphan adopted: true\n\
         the worker took its SIGCHLD: true\nreaped: true\n"
    );
}

/// A process that becomes a subreaper does not adopt an orphan below it
/// that had its adopter already, unless that adopter is a subreaper below
/// it which then ends; an orphan it adopted that stops and
/// continues is reported to its `wait` (`WUNTRACED`, `WCONTINUED`) and
/// with `SIGCHLD`, once each, as a child's stop and continue are.
#[test]
fn subreaper_adoption_and_stops() {
    assert_eq!(
        namespaces("subreaper-late"),
        "child exited 0\nchild is not a subreaper: true\norphan's parent is another: true\n\
         and stays so: true\nnothing to wait for: true\n"
    );
    assert_eq!(
        namespaces("subreaper-handover"),
        "adopted below: true\nhanded up: true\nreaped: true, killed by 9\n"
    );
    assert_eq!(
        namespaces("subreaper-stop"),
        "child exited 0\nchild is not a subreaper: true\nnothing yet: true\n\
         stopped: true, by 19\nSIGCHLD for the stop: true\nreported once: true\n\
         continued: true\nSIGCHLD for the continue: true\nreaped: true, killed by 9\n"
    );
}

/// A child killed outright while its parent lives is that parent's zombie;
/// once the parent ends, the subreaper is sent `SIGCHLD` for it and reaps
/// it as killed.
#[test]
fn subreaper_adopts_a_killed_zombie() {
    assert_eq!(
        namespaces("subreaper-zombie"),
        "SIGCHLD for the killed orphan: true\nreaped it: true, killed by 9\n"
    );
}

/// A pid namespace's init cannot be killed with `SIGKILL` from inside its
/// namespace, by itself or a child, as Linux shields it.
#[test]
fn pid_namespace_init_is_unkillable_from_inside() {
    assert_eq!(
        namespaces("init-unkillable"),
        "init kills itself: 0\nchild kills init: 0\ninit lives\ninit exited 4\n"
    );
}

/// A pid namespace's init adopts the orphans in it, and when it ends, or
/// is killed, the rest of its namespace is killed, before its parent's
/// `wait` reports it.
#[test]
fn pid_namespace_init_reaps_and_ends_its_namespace() {
    assert_eq!(
        namespaces("pid-orphan"),
        "child exited 0\nchild is not a subreaper: true\norphan's parent: 1\n\
         init reaped the orphan: true, exited 5\ninit exited 0\n"
    );
    assert_eq!(
        namespaces("init-death"),
        "init exited 3: the rest ended first: true\ninit killed by 9: the rest ended first: true\n"
    );
}

/// A pid namespace's init killed from outside fwe, by the host's
/// `SIGKILL`, which it cannot see coming, takes its namespace with it at
/// once, before its parent reaps it.
#[test]
fn pid_namespace_ends_with_an_init_killed_from_outside() {
    let file = std::env::temp_dir()
        .join(format!("fwe-ns-{}-init-killed", std::process::id()))
        .join("tmp/init-pid");
    let killer = std::thread::spawn(move || {
        for _ in 0..3000 {
            if let Some(pid) = std::fs::read_to_string(&file).ok().and_then(|s| s.parse().ok()) {
                // SAFETY: plain call, to the guest's init (a host pid in
                // fwe's initial pid namespace).
                unsafe { libc::kill(pid, libc::SIGKILL) };
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    });
    let out = namespaces("init-killed");
    assert!(killer.join().unwrap());
    assert_eq!(out, "the rest ended unreaped: true\ninit killed by 9\n");
}

/// Run one scenario of the `containers` guest in a root filesystem of its
/// own (`/tmp`, and `/etc` with `marker`) and return its output.
fn containers(scenario: &str) -> String {
    let root = std::env::temp_dir().join(format!("fwe-ct-{}-{scenario}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    for d in ["tmp", "etc"] {
        std::fs::create_dir_all(root.join(d)).unwrap();
    }
    std::fs::write(root.join("etc/marker"), "marked\n").unwrap();
    std::fs::copy(rust_guest("containers"), root.join("containers")).unwrap();
    if scenario == "exec-low" {
        std::fs::copy(rust_low_guest("hello"), root.join("lowprog")).unwrap();
    }
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fwe"));
    cmd.arg("--strace=failures")
        .arg("--root")
        .arg(&root)
        .arg(root.join("containers"))
        .arg(scenario);
    let out = run_bounded(cmd);
    eprintln!("--- containers {scenario} stderr:\n{}", String::from_utf8_lossy(&out.stderr));
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(out.status.code(), Some(0), "{scenario}: {}", stdout(&out));
    stdout(&out)
}

/// A user's own user namespace, whose root is the user: a program run
/// there is root's, with every capability (root is uid 0 of the process's
/// namespace, not of the initial one).
#[test]
fn root_of_a_users_namespace_keeps_capabilities_across_exec() {
    assert_eq!(
        containers("userns-exec"),
        "root of its namespace: euid 0 CapEff:\t000001ffffffffff\n"
    );
}

/// A user namespace a user made is the user's to join (it has every
/// capability there), not another user's.
#[test]
fn a_users_namespace_is_its_makers_to_join() {
    assert_eq!(containers("userns-join"), "its maker joins: ok\nanother user joins: EPERM\n");
}

/// A program only the VM can run (linked below 4 GiB), where there is no
/// VM (no stand-in, no entitlement): `execve` fails with `ENOEXEC` while the
/// caller is intact, and the caller goes on.
#[test]
fn exec_of_a_vm_program_without_a_vm_fails_cleanly() {
    assert_eq!(containers("exec-low"), "exec: ENOEXEC, and on\n");
}

/// What a program gives the user who runs it: file capabilities
/// (`security.capability`, as `newuidmap` has `cap_setuid+ep`) raise its
/// capabilities, a set-user-ID root program its effective uid and with it
/// every capability; under `no_new_privs`, neither.
#[test]
fn programs_grant_file_capabilities_and_set_ids() {
    assert_eq!(
        containers("execprivs"),
        "setcap: ok\ncapped: euid 1000 CapEff:\t0000000000000080\n\
         set-uid: euid 0 CapEff:\t000001fffdffffff\n\
         capped, no_new_privs: euid 1000 CapEff:\t0000000000000000\n\
         set-uid, no_new_privs: euid 1000 CapEff:\t0000000000000000\n\
         a user's mknod: whiteout ok, device EPERM\n\
         /proc owners: theirs Ok(1000), opened Ok(1000), own Ok(0)\n"
    );
}

/// Extended attributes by Linux's namespaces: set, created once, read
/// (and measured), listed, removed; `system.` (ACLs) and a name in no
/// namespace are not kept; `user.` ones are for files, not links.
#[test]
fn extended_attributes() {
    assert_eq!(
        containers("xattr"),
        "user: ok\ntrusted: ok\nagain, create: EEXIST\nacl: EOPNOTSUPP\n\
         no namespace: EOPNOTSUPP\nget: y\nsize: 1\nmissing: ENODATA\n\
         list: trusted.overlay.opaque user.a\nremove: ok\nuser on a link: EPERM\n\
         trusted on a link: ok\n"
    );
}

/// An overlay mount: lookups and listings merge the layers; a write copies
/// the file up, a removal leaves a whiteout, a directory a lower layer has
/// cannot be renamed, a directory made again hides the lower one's
/// entries; a file opened in a lower layer and changed through its
/// descriptor is copied up; the lower layers are never changed. Without an
/// upper layer an overlay is read-only, and an option fwe lacks is refused.
#[test]
fn overlay_mounts() {
    assert_eq!(
        containers("overlay"),
        "mount: ok\na: lower1\nd: x y z\na written: lower1+ lower: lower1 upper: lower1+\n\
         unlink: ok\ngone: ENOENT lower: g whiteout: true 0\nrename a lower dir: EXDEV\n\
         rename a file: ok\nd: x2 y z lower: x y\nrmdir full: ENOTEMPTY\nrmdir: ok\n\
         made again: ok holds: []\nopaque in upper: y\n\
         opaque through the overlay: EOPNOTSUPP\nfchmod: ok\ne: 600 lower: 644 upper: 600\n\
         f_type: 0x794c7630\nmountinfo: true\nfilesystems: true\nroot: a d deep sub\n\
         upper: a d deep gone sub\numount: ok\nread-only mount: ok a: lower1+\nwrite: EROFS\n\
         metacopy: EINVAL\n"
    );
}

/// What container runtimes ask beyond the namespaces, as containerd's shim
/// and runc ask it: an `O_PATH` descriptor of a FIFO is no reader of it and
/// stats as it; a FIFO's open waits for its other end while the process's
/// other threads run on, and its reader sees its writer go in `epoll` and
/// `poll`; `/proc` shows namespace links as their namespaces, `fdinfo`,
/// another process's descriptors, `oom_score_adj` (inherited), and is
/// procfs to `fstatfs`; `SO_PEERCRED`; `shutdown` once the peer has gone;
/// `CLONE_PARENT`; `AT_EMPTY_PATH`; a BPF program of another type loads but
/// is not attached; limits set with `prlimit` from outside; netlink of a
/// network namespace's `lo`, and in the host's, the host's loopback, up
/// and kept so.
#[test]
fn container_runtime_calls() {
    assert_eq!(
        containers("runtime-calls"),
        "stat \"\": ENOENT\nwriter with only an O_PATH: ENXIO\nO_PATH fstat is a FIFO: true\n\
         its link: /tmp/ff\nanother thread ran\nopened the FIFO: true\ndata: 1\n\
         writer gone: 1 hup true\npoll: hup true\nthen: 0\nns inode matches: true\n\
         fdinfo: true\nproc fstatfs: 0x9fa0\noom: 500 child's fd 9: /etc/marker\n\
         prlimit of the child: ok\nchild: oom 500 nofile 100 200\npeer: self true uid 0\n\
         shutdown after the peer: ok\nCLONE_PARENT's parent is the grandparent: true\n\
         linkat AT_EMPTY_PATH: ok\nfchownat AT_EMPTY_PATH: ok\nskb program loads: true type 8: true\n\
         attached as a device program: EINVAL\nnetlink outside: true lo flags 0x10049, set down -1\n\
         netlink inside: true\nlo flags: 0x8\nset up: 0\nlo flags then: 0x10049\n"
    );
}

/// Descriptor edges container runtimes reach: an `O_PATH | O_NOFOLLOW`
/// descriptor of a symbolic link (its stat, link, close-on-exec, fdinfo,
/// access and times through `AT_EMPTY_PATH`); `epoll` reporting one event
/// per descriptor, one-shot entries once until re-armed, and a FIFO's
/// writers gone once to one-shot and edge-triggered entries, and nothing
/// taken from its reader by another process waiting on it; a signal
/// ending a wait on a FIFO; `oom_adj`'s scale, the floor a privileged write
/// sets, and another user's `/proc` files.
#[test]
fn container_descriptor_edges() {
    assert_eq!(
        containers("fd-edges"),
        "link: true S_IFLNK true\nreadlinkat \"\": target-x\n\
         readlinkat \"\" of a file: ENOENT\ncloexec: 0 1\nfdinfo O_PATH: true\n\
         faccessat2 \"\": ok bad flags: EINVAL\nutimensat \"\": ok\nlink's mtime: 2000\n\
         events: 1 bits 0x5\none-shot: 1 0 re-armed 1\nFIFO one-shot: 1 hup true then 0\n\
         FIFO edge-triggered: 1 hup true then 0\nFIFO level-triggered: 1 then 1\n\
         reader got: 200\nppoll: EINTR\nepoll_wait: EINTR\noom_adj 15: 1000 500: 8 -17: -1000\n\
         user: below the floor EACCES above ok parent's EACCES\n\
         child's Uid: 1000 1000 1000 1000; root opens its oom_score_adj: ok\n"
    );
}

/// An overlay keeps its layers' own directories theirs, makes nothing for
/// `O_PATH`, follows a directory moved since it was opened, keeps a
/// descriptor on its own file when another is renamed over it, reads a
/// listing on across its directory's copy-up and seeks in it, hides what a
/// whiteout hid when directories are exchanged, refuses a whiteout made by
/// hand, never writes a lower layer through a descriptor that outlived the
/// mount, and refuses an upper layer in a read-only mount.
#[test]
fn overlay_edge_cases() {
    assert_eq!(
        containers("overlay-edges"),
        "mount: ok\nlayer's own: true not upper: true\nO_PATH|O_CREAT: ENOENT then: ENOENT\n\
         moved dir: true\nrenamed over: ESTALE still reads: lower\n\
         listing across copy-up: 8 entries, 8 distinct\nseek to 3: true\n\
         exchange: ok h holds: []\nmknod 0:0: EPERM\nafter unmount: upper true lower false\n\
         read-only upper: EROFS\n"
    );
}

/// Root passes permission bits, also of modes that deny every access, which
/// `stat` shows as they are; a process without the capabilities is held to
/// them.
#[test]
fn root_passes_permission_bits() {
    assert_eq!(
        containers("modes"),
        "dir: 555\nroot makes a file in it: ok\nfile: 0\nroot writes it: ok\n\
         user reads it: EACCES\nuser makes a file: EACCES\ndir after chmod: 755\n"
    );
}

/// Two processes reading one `SOCK_SEQPACKET` socket at once each take
/// whole messages, though they arrive in pieces; a child forked while a
/// thread of its parent waits in a receive on a socket receives from it.
#[test]
fn seqpacket_shared_between_processes() {
    assert_eq!(
        containers("seqpacket-shared"),
        "whole: 40 torn: 0\nthread got: 5\nchild got one: true\n"
    );
}

/// A listening `SOCK_SEQPACKET` Unix socket: messages keep their
/// boundaries, one longer than the buffer is cut (`MSG_TRUNC`), and the
/// peer's close is end-of-file that `epoll` reports.
#[test]
fn seqpacket_listener() {
    assert_eq!(
        containers("seqpacket"),
        "bind: ok\ngot 3 \"one\" cut false\ngot 3 \"two\" cut false\n\
         got 5 \"hello\" cut true\nnothing yet: 0\npeer gone: 1 in true hup true\n\
         end of file: 0\n"
    );
}

/// `SOCK_SEQPACKET` messages bigger than a host socket's default buffers
/// are sent and taken without blocking, and looked at whole first; a bad
/// buffer is `EFAULT`; a socket passed with `SCM_RIGHTS` is one of its kind
/// in the receiver too.
#[test]
fn seqpacket_large_peeked_and_passed() {
    assert_eq!(
        containers("seqpacket-more"),
        "non-blocking send: 20000\npeek: 20000 same true\ntake: 20000 same true\n\
         nothing left: -1\nbad buffer: -1 EFAULT\npassed: 1\nreceived socket type: 5\n\
         through it: 2 \"m1\"\nthrough it: 3 \"m22\"\n"
    );
}

/// `/proc/self/fd/N`, `cwd` and `root` lead out of `/proc` in the middle of
/// a path, as Linux's magic links do.
#[test]
fn proc_magic_links() {
    assert_eq!(
        containers("proc-links"),
        "made through the fd: ok\nthere: true\nthrough cwd: marked\nthrough root: marked\n\
         cwd: /etc\n"
    );
}

/// A network namespace has sysctls of its own, checked as Linux checks
/// them, a new one's from Linux's defaults; root sets the initial one's.
#[test]
fn network_namespace_sysctls() {
    assert_eq!(
        containers("sysctl"),
        "initial: 1 0\ninitial write: ok\nnew: 1 0\n\
         set: 0 2147483647\nbackwards: 1 0\ninitial after: 0 0\n\
         listed: [\"ping_group_range\"]\n"
    );
}

/// A Unix socket's node has the socket's mode (every bit, or what `fchmod`
/// gave it) less the umask, and a path under a long root binds and
/// connects.
#[test]
fn unix_socket_nodes() {
    assert_eq!(
        containers("sockets"),
        "plain: 755\nfchmod 660: 640\nlong bind: ok\nlong connect: ok\nmissing: ENOENT\n"
    );
}

/// `--strace-file` traces every process of a run to one file, each line
/// naming its process: here a parent and the child it forks.
#[test]
fn strace_file_follows_children() {
    let root = std::env::temp_dir().join(format!("fwe-trace-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("tmp")).unwrap();
    std::fs::copy(rust_guest("containers"), root.join("containers")).unwrap();
    let log = root.with_extension("log");
    let _ = std::fs::remove_file(&log);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fwe"));
    cmd.arg("--strace")
        .arg(format!("--strace-file={}", log.display()))
        .arg("--root")
        .arg(&root)
        .arg(root.join("containers"))
        .arg("modes");
    let out = run_bounded(cmd);
    let trace = std::fs::read_to_string(&log).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_file(&log);
    assert_eq!(out.status.code(), Some(0));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("mkdirat("), "traced to stderr");
    let pids: std::collections::BTreeSet<&str> =
        trace.lines().filter_map(|l| l.strip_prefix("[fwe ")?.split(']').next()).collect();
    assert_eq!(pids.len(), 2, "{pids:?}");
    assert!(trace.contains("setuid("), "the child's calls are there");
}
