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

const ASM_GUESTS: &[&str] = &["hello", "exit42", "enosys", "regs", "x18spin", "tpidr"];

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
                    .args(["-flavor", "gnu", "-static", "--image-base=0x2000000000", "-o"])
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
            .arg(out.join("rust"));
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
    let code = fwe(&asm_guest("regs-pie"), &[]).status.code();
    let meaning = match code {
        Some(0) => "preserved",
        Some(1) => "x18 lost",
        Some(2) => "TPIDR_EL0 lost",
        Some(3) => "a general-purpose register lost",
        _ => "crashed",
    };
    assert_eq!(code, Some(0), "register state: {meaning}");
}

/// x18 across preemption alone, with no system calls in the loop.
#[test]
fn asm_x18_survives_preemption() {
    assert_eq!(fwe(&asm_guest("x18spin-pie"), &[]).status.code(), Some(0));
}

/// TPIDR_EL0 (the Linux thread pointer) across trapped system calls.
#[test]
fn asm_tpidr_survives_syscalls() {
    assert_eq!(fwe(&asm_guest("tpidr-pie"), &[]).status.code(), Some(0));
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

#[test]
fn rust_runtime_services() {
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
