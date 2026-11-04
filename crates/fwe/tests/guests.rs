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
/// and only a group still alive 5 s later gets `SIGKILL`. Afterwards no
/// process of the group may be left (a fork child outliving its test would
/// keep a VM running alongside the next one): the test fails if one is.
fn run_vm_bounded(mut cmd: Command) -> Output {
    use std::os::unix::process::CommandExt;
    cmd.stdin(Stdio::null()).process_group(0);
    let out = run_bounded_inner(cmd, &[], GUEST_TIMEOUT, true);
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
                let _ = child.kill();
            }
            break child.wait().unwrap();
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    if timed_out {
        eprintln!("--- guest timed out after {limit:?} (killed)");
    }
    // Readers finish once the pipes close (at process exit).
    let stdout = out_reader.join().unwrap();
    let stderr = err_reader.join().unwrap();
    (Output { status, stdout, stderr }, child.id() as i32)
}

const ASM_GUESTS: &[&str] = &[
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
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fwe"));
    cmd.arg("--strace").arg(program).args(args).env("FWE_GUEST_VAR", "from-host");
    let out = run_vm_bounded(cmd);
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
    let out = out_dir().join("c");
    std::fs::create_dir_all(&out).unwrap();
    let tag =
        if pie { name_suffix(libc).to_string() } else { format!("{}-nopie", name_suffix(libc)) };
    let obj = out.join(format!("{name}-{tag}.o"));
    run_checked(
        Command::new("clang")
            .args([
                "--target=aarch64-linux-gnu",
                "-O2",
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
    // About 12 s alone: git's commands start many git processes, each a
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

/// A signal from another process reaches a guest handler (through the host),
/// with the sender's pid in `siginfo`, and wakes `sigsuspend`.
#[test]
fn signal_from_child_reaches_parent_handler() {
    assert_eq!(signals("notify-parent"), "SIGUSR1 from child: true\nexited 0\n");
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

/// `ppoll` waits under the mask it is given, so a signal blocked outside it
/// interrupts it and runs the handler.
#[test]
fn ppoll_applies_its_signal_mask() {
    assert_eq!(signals("ppoll-mask"), "ppoll -1 errno 4, handled 1\n");
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
}

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

/// `RLIMIT_NOFILE` is virtual: its hard limit is where fwe's own range
/// begins, so `dup2` there fails with `EBADF` and raising it is refused.
#[test]
fn descriptor_limit_bounds_the_guest() {
    assert_eq!(
        fds("limits"),
        "hard limit above soft: true\ndup2 at the hard limit: -1 EBADF\ndup2 just below it: true\n\
         raising past it: -1 EPERM\nsoft limit now 256\n"
    );
}

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
// These run only where Hypervisor.framework works: a bare-metal Apple Silicon
// Mac (not GitHub's hosted runners, which are VMs themselves). There `fwe` is
// copied and signed with the hypervisor entitlement; elsewhere the tests
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

/// `fwe` signed with the hypervisor entitlement, if this host can run a VM.
fn hv_fwe() -> Option<&'static Path> {
    static FWE: OnceLock<Option<PathBuf>> = OnceLock::new();
    FWE.get_or_init(|| {
        // FWE_NO_HV=1 skips the VM tests on a machine that could run them.
        if std::env::var_os("FWE_NO_HV").is_some() {
            return None;
        }
        // Never alongside another hypervisor client: the machine crashed
        // three times while one (Podman's krunkit, with nested
        // virtualization) ran beside these tests (docs/hypervisor.md).
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
    })
    .as_deref()
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
            "-C linker-flavor=ld.lld -C link-self-contained=yes -C target-feature=+crt-static",
        );
        run_checked(&mut build);
        out
    });
    dir.join("aarch64-unknown-linux-musl/release").join(name)
}

/// Held while a VM process runs, so the tests never run more than one at a
/// time: Hypervisor.framework is shared with whatever else on the machine
/// uses it, and the tests should not stress it.
static ONE_VM: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Run `program` under the signed `fwe`, or `None` (test skipped) when this
/// host cannot run the hypervisor backend.
fn fwe_hv(program: &Path, args: &[&str]) -> Option<Output> {
    let Some(fwe) = hv_fwe() else {
        eprintln!("skipped: no hypervisor on this host");
        return None;
    };
    let _one = ONE_VM.lock().unwrap_or_else(|e| e.into_inner());
    let mut cmd = Command::new(fwe);
    cmd.arg("--strace").arg(program).args(args).env("FWE_GUEST_VAR", "from-host");
    let out = run_vm_bounded(cmd);
    eprintln!("--- hv {} stderr:\n{}", program.display(), String::from_utf8_lossy(&out.stderr));
    Some(out)
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
    assert!(stdout(&out).contains("dup2 at the hard limit: -1 EBADF"));
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
    let Some(fwe) = hv_fwe() else {
        eprintln!("skipped: no hypervisor on this host");
        return None;
    };
    let _one = ONE_VM.lock().unwrap_or_else(|e| e.into_inner());
    let mut cmd = Command::new(fwe);
    cmd.arg("--strace").arg("--root").arg(root).arg(program).args(args);
    let out = run_vm_bounded(cmd);
    eprintln!("--- hv {} stderr:\n{}", program.display(), String::from_utf8_lossy(&out.stderr));
    Some(out)
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
    let _one = ONE_VM.lock().unwrap_or_else(|e| e.into_inner());
    let mut cmd = Command::new(hv_fwe().unwrap());
    cmd.arg("--strace")
        .arg("--root")
        .arg(root)
        .arg(debian_bin("bash"))
        .args(["-c", "cd /lib && /hello-low; echo status=$? cwd=$PWD"])
        .env_clear()
        .env("LD_LIBRARY_PATH", "/lib")
        .env("PATH", "/bin");
    let out = run_vm_bounded(cmd);
    eprintln!("--- bash -> vm stderr:\n{}", String::from_utf8_lossy(&out.stderr));
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
        ("fork-snapshot", "consistent snapshots: 8 of 8\n"),
        ("waitid", "exited: true, status 6, pid matches: true\nkilled: true, signal 9\n"),
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
