//! fwe's Linux Vulkan driver's files, as a Linux program finds them: its
//! manifest and its library in `/etc/vulkan/icd.d` ([`PLACE`]), a directory
//! a Linux Vulkan loader reads drivers' manifests from, and which fwe
//! answers itself, as it answers `/dev`'s nodes ([`crate::fs`]). Linux's
//! Vulkan packages (the loader, Mesa's drivers) put theirs in
//! `/usr/share/vulkan/icd.d`, which stays the rootfs's.
//!
//! The files are fwe's, written once (read-only) to a directory of fwe's
//! named for their contents, so each build of fwe has its own.

use fwe_abi::errno;

/// Where the guest finds the files.
pub const PLACE: &[u8] = b"/etc/vulkan/icd.d";
/// The manifest's name.
pub const MANIFEST: &[u8] = b"fwe_icd.aarch64.json";
/// The library's name.
pub const LIBRARY: &[u8] = b"libvulkan_fwe.so";

/// The library, built for this fwe (`crates/kernel/build.rs`).
#[cfg(target_os = "macos")]
static LIBRARY_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/libvulkan_fwe.so"));
#[cfg(not(target_os = "macos"))]
static LIBRARY_BYTES: &[u8] = &[];

/// The manifest: the library, at its place, and the Vulkan version of
/// fwe's commands.
pub fn manifest() -> Vec<u8> {
    let library =
        String::from_utf8_lossy(PLACE).into_owned() + "/" + &String::from_utf8_lossy(LIBRARY);
    format!(
        "{{\n    \"file_format_version\": \"1.0.1\",\n    \"ICD\": {{\n        \
         \"library_path\": \"{library}\",\n        \"api_version\": \"{}\"\n    }}\n}}\n",
        super::generated::REGISTRY
    )
    .into_bytes()
}

/// The host directory whose `icd.d` holds the files, written on first use.
pub fn dir() -> Result<Vec<u8>, i32> {
    if LIBRARY_BYTES.is_empty() {
        return Err(errno::ENODEV);
    }
    let manifest = manifest();
    let id = fnv(&[LIBRARY_BYTES, &manifest]);
    let base = crate::mounts::join(
        &crate::fs::shm::user_dir()?,
        format!("v{}-vulkan-{id:016x}", crate::shared::FORMAT).as_bytes(),
    );
    let icd = crate::mounts::join(&base, b"icd.d");
    if exists(&crate::mounts::join(&icd, LIBRARY)) {
        return Ok(base);
    }
    // Built beside it and moved into place whole, so another process sees
    // all of it or none.
    let mut building = base.clone();
    building.extend_from_slice(format!(".building-{}", crate::host::pid()).as_bytes());
    let inner = crate::mounts::join(&building, b"icd.d");
    // What an attempt of an earlier process of this pid left.
    let _ = set_mode(&inner, 0o755);
    let _ = std::fs::remove_dir_all(os(&building));
    std::fs::create_dir_all(os(&inner)).map_err(io)?;
    for (name, bytes) in [(MANIFEST, &manifest[..]), (LIBRARY, LIBRARY_BYTES)] {
        let path = crate::mounts::join(&inner, name);
        std::fs::write(os(&path), bytes).map_err(io)?;
        set_mode(&path, 0o444)?;
    }
    set_mode(&inner, 0o555)?;
    match std::fs::rename(os(&building), os(&base)) {
        Ok(()) => Ok(base),
        // Another process put it in place first.
        Err(_) if exists(&crate::mounts::join(&icd, LIBRARY)) => {
            set_mode(&inner, 0o755)?;
            let _ = std::fs::remove_dir_all(os(&building));
            Ok(base)
        }
        Err(e) => Err(io(e)),
    }
}

fn os(path: &[u8]) -> &std::path::Path {
    use std::os::unix::ffi::OsStrExt;
    std::path::Path::new(std::ffi::OsStr::from_bytes(path))
}

fn exists(path: &[u8]) -> bool {
    os(path).exists()
}

fn set_mode(path: &[u8], mode: u32) -> Result<(), i32> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(os(path), std::fs::Permissions::from_mode(mode)).map_err(io)
}

fn io(e: std::io::Error) -> i32 {
    e.raw_os_error()
        .map_or(errno::EIO, |r| crate::host::errno_to_linux(crate::host::HostErrno::new(r)))
}

/// FNV-1a over `parts`.
fn fnv(parts: &[&[u8]]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for part in parts {
        for &b in *part {
            h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
        }
    }
    h
}

/// Where in fwe's directory of the files guest path `name` is, `name`
/// being `icd.d` or a name in it (from [`PLACE`]'s parent on): the host
/// directory and the name in it.
pub fn place(name: &[u8]) -> Result<(Vec<u8>, Vec<u8>), i32> {
    let base = dir()?;
    match name.strip_prefix(b"icd.d/") {
        Some(file) => Ok((crate::mounts::join(&base, b"icd.d"), file.to_vec())),
        None => Ok((base, name.to_vec())),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_manifest_names_the_library_at_its_place() {
        let m = String::from_utf8(super::manifest()).unwrap();
        assert!(m.contains("\"library_path\": \"/etc/vulkan/icd.d/libvulkan_fwe.so\""), "{m}");
        assert!(m.contains(&format!("\"api_version\": \"{}\"", super::super::generated::REGISTRY)));
    }
}
