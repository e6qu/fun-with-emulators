fn main() {
    // Linux executables are commonly linked at low addresses (0x10000 for Go,
    // 0x200000 or 0x400000 for C and Rust). macOS reserves the low 4 GiB of
    // every arm64 process with __PAGEZERO by default, so shrink it to one
    // page to leave that range free for guests.
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if os == "macos" {
        println!("cargo:rustc-link-arg-bins=-Wl,-pagezero_size,0x4000");
    }
}
