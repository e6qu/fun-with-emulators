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
use std::process::{Command, Output};
use std::sync::OnceLock;

const ASM_GUESTS: &[&str] =
    &["hello", "exit42", "enosys", "regs", "tpidr", "x18", "x18spin", "fileio"];

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
    let out = Command::new(env!("CARGO_BIN_EXE_fwe"))
        .arg("--strace")
        .arg(program)
        .args(args)
        .env("FWE_GUEST_VAR", "from-host")
        .output()
        .unwrap();
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
        let out = Command::new(env!("CARGO_BIN_EXE_fwe"))
            .arg("--strace")
            .arg("--root")
            .arg(&root)
            .arg(asm_guest(name))
            .output()
            .unwrap();
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

    let out = Command::new(env!("CARGO_BIN_EXE_fwe"))
        .arg("--strace")
        .arg("--root")
        .arg(&root)
        .arg(&dynprog)
        .output()
        .unwrap();
    eprintln!("--- dynprog stderr:\n{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(stdout(&out), "dynamic handoff ok\n");
    assert_eq!(out.status.code(), Some(0));
    let _ = std::fs::remove_dir_all(&root);
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

/// Whether this host preserves x18, as reported by `fwe --host-info`.
fn host_preserves_x18() -> bool {
    let out = Command::new(env!("CARGO_BIN_EXE_fwe")).arg("--host-info").output().unwrap();
    let info = String::from_utf8_lossy(&out.stdout).into_owned();
    eprintln!("host info: {info}");
    info.contains("x18 preserved: yes")
}

/// x18 across trapped system calls, where the host supports preserving it.
#[test]
fn asm_x18_survives_syscalls() {
    if !host_preserves_x18() {
        eprintln!("skipped: host does not preserve x18");
        return;
    }
    assert_eq!(fwe(&asm_guest("x18-pie"), &[]).status.code(), Some(0));
}

/// x18 across preemption alone, where the host supports preserving it.
#[test]
fn asm_x18_survives_preemption() {
    if !host_preserves_x18() {
        eprintln!("skipped: host does not preserve x18");
        return;
    }
    assert_eq!(fwe(&asm_guest("x18spin-pie"), &[]).status.code(), Some(0));
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

/// Compiled Linux code uses x18 as a scratch register, and macOS clears x18
/// on exception return (page faults, preemption) unless the custom x18 ABI
/// keeps it. Without that, heavier programs fail at random; rewriting x18
/// uses for older macOS is on the roadmap.
#[test]
fn rust_runtime_services() {
    if !host_preserves_x18() {
        eprintln!("skipped: host does not preserve x18");
        return;
    }
    let out = fwe(&rust_guest("sysinfo"), &[]);
    assert_eq!(
        stdout(&out),
        "heap ok: 10000 entries, 314616 bytes\nsleep ok: true\nclock ok: true\nlarge allocation ok: true\n"
    );
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn low_link_address_is_rejected_cleanly() {
    let out = fwe(&asm_guest("hello-low"), &[]);
    assert_eq!(out.status.code(), Some(126));
    assert!(String::from_utf8_lossy(&out.stderr).contains("below 4 GiB"));
}

#[test]
fn rejects_non_elf() {
    let this_file = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/guests.rs");
    let out = Command::new(env!("CARGO_BIN_EXE_fwe")).arg(this_file).output().unwrap();
    assert_eq!(out.status.code(), Some(126));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not an ELF file"));
}
