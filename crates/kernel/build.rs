//! Builds fwe's Linux Vulkan driver, `libvulkan_fwe.so` (`driver/vulkan/`),
//! for a macOS build of fwe, which serves it to Linux programs
//! ([`crate::vulkan`]). It is an aarch64 Linux shared library, freestanding:
//! compiled by clang and linked by the Rust toolchain's `rust-lld`, as the
//! tests' guests are. Other builds need neither.

use std::path::{Path, PathBuf};
use std::process::Command;

const SOURCES: [&str; 3] = ["icd.c", "generated.c", "wsi.c"];

fn main() {
    let dir = Path::new(env("CARGO_MANIFEST_DIR").as_str()).join("../../driver/vulkan");
    println!("cargo:rerun-if-changed={}", dir.display());
    if env("CARGO_CFG_TARGET_OS") != "macos" {
        return;
    }
    let out = PathBuf::from(env("OUT_DIR"));
    let mut objects = Vec::new();
    for source in SOURCES {
        let object = out.join(source).with_extension("o");
        run(Command::new("clang")
            .args([
                "--target=aarch64-linux-gnu",
                "-ffreestanding",
                "-nostdlib",
                "-fPIC",
                "-O2",
                "-fno-stack-protector",
                "-fvisibility=hidden",
                "-mbranch-protection=standard",
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-c",
            ])
            .arg(dir.join(source))
            .arg("-o")
            .arg(&object));
        objects.push(object);
    }
    run(Command::new(rust_lld())
        .args([
            "-flavor",
            "gnu",
            "-shared",
            "-soname",
            "libvulkan_fwe.so",
            "--hash-style=both",
            "-z",
            "now",
            "-z",
            "relro",
            // Every symbol the library uses is its own (the C library's it
            // may use are weak): a command of the window systems' that
            // wsi.c lacks fails here.
            "-z",
            "defs",
            "--no-undefined-version",
            "-o",
        ])
        .arg(out.join("libvulkan_fwe.so"))
        .args(&objects));
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is unset"))
}

/// The Rust toolchain's `rust-lld`.
fn rust_lld() -> PathBuf {
    let rustc = env("RUSTC");
    let print = |what: &str| {
        let o = Command::new(&rustc).args(["--print", what]).output().expect("rustc runs");
        String::from_utf8(o.stdout).expect("rustc prints text").trim().to_string()
    };
    Path::new(&print("sysroot")).join("lib/rustlib").join(print("host-tuple")).join("bin/rust-lld")
}

fn run(cmd: &mut Command) {
    let status = cmd.status().unwrap_or_else(|e| panic!("{cmd:?}: {e}"));
    assert!(status.success(), "{cmd:?}: {status}");
}
