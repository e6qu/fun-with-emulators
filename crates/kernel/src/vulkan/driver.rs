//! The Mac's Vulkan driver, loaded into fwe's process as a Vulkan loader
//! loads a driver: its manifest names its library, which is opened with
//! `dlopen` and asked for its loader interface
//! (`vk_icdNegotiateLoaderICDInterfaceVersion`, at most version 7) and its
//! functions (`vk_icdGetInstanceProcAddr`). No host Vulkan loader stands
//! between: the guest's own loader is the one the program has.
//!
//! The driver is the one whose manifest `FWE_VULKAN_DRIVER` names, else
//! the first installed of KosmicKrisp (Homebrew's `mesa`) and MoltenVK
//! (Homebrew's `molten-vk`).

use std::ffi::{CStr, CString, c_char, c_void};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// The manifests searched, in order, when `FWE_VULKAN_DRIVER` names none.
pub const MANIFESTS: [&str; 2] = [
    "/opt/homebrew/share/vulkan/icd.d/kosmickrisp_mesa_icd.aarch64.json",
    "/opt/homebrew/etc/vulkan/icd.d/MoltenVK_icd.json",
];

/// The newest loader interface fwe speaks to a driver.
const INTERFACE: u32 = 7;

pub type GetProcAddr = unsafe extern "C" fn(*mut c_void, *const c_char) -> *const c_void;
type Negotiate = unsafe extern "C" fn(*mut u32) -> i32;

/// A driver, loaded.
pub struct Driver {
    /// Its `vk_icdGetInstanceProcAddr`.
    pub get_instance_proc_addr: GetProcAddr,
    /// The loader interface it agreed to.
    pub interface: u32,
    /// A portability driver (one that implements Vulkan only in part, as
    /// MoltenVK does on Metal): its instances are made with
    /// `VK_KHR_portability_enumeration`, and its devices with
    /// `VK_KHR_portability_subset`.
    pub portability: bool,
    /// Its manifest.
    pub manifest: PathBuf,
}

// SAFETY: the driver's functions are callable from any thread (Vulkan's
// rules on which objects calls may share are the program's to keep, as
// they are with a loader's driver).
unsafe impl Send for Driver {}
// SAFETY: as above; nothing in `Driver` changes after loading.
unsafe impl Sync for Driver {}

static DRIVER: OnceLock<Result<Driver, String>> = OnceLock::new();

/// The driver, loaded on first use; or why there is none.
pub fn get() -> Result<&'static Driver, &'static str> {
    DRIVER.get_or_init(load).as_ref().map_err(|e| e.as_str())
}

/// Whether a driver has been loaded into this process (by this program or
/// one before it in the process).
pub fn loaded() -> bool {
    matches!(DRIVER.get(), Some(Ok(_)))
}

/// The manifest of the driver to load: `FWE_VULKAN_DRIVER`'s, else the
/// first of [`MANIFESTS`] installed.
pub fn manifest() -> Result<PathBuf, String> {
    if let Some(m) = std::env::var_os("FWE_VULKAN_DRIVER") {
        return Ok(PathBuf::from(m));
    }
    MANIFESTS.iter().map(PathBuf::from).find(|m| m.exists()).ok_or_else(|| {
        "no Vulkan driver installed (Homebrew's mesa or molten-vk), and FWE_VULKAN_DRIVER unset"
            .to_string()
    })
}

/// Whether a driver is there to load (as it was when first asked: the
/// device is there for the process's life).
pub fn installed() -> bool {
    static INSTALLED: OnceLock<bool> = OnceLock::new();
    *INSTALLED.get_or_init(|| manifest().is_ok_and(|m| m.exists()))
}

fn load() -> Result<Driver, String> {
    let manifest = manifest()?;
    let text =
        std::fs::read_to_string(&manifest).map_err(|e| format!("{}: {e}", manifest.display()))?;
    let library = json_string(&text, "library_path")
        .ok_or_else(|| format!("{}: no ICD.library_path", manifest.display()))?;
    let path = library_path(&manifest, &library);
    let portability = json_bool(&text, "is_portability_driver").unwrap_or(false);
    let c = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| format!("{}: a NUL in the library's path", manifest.display()))?;
    // SAFETY: a NUL-terminated path. The library is never closed: its
    // objects live as long as the process may use them.
    let lib = unsafe { libc::dlopen(c.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    if lib.is_null() {
        // SAFETY: `dlerror` returns the last error's text or NULL.
        let why = unsafe { libc::dlerror() };
        let why = if why.is_null() {
            String::new()
        } else {
            // SAFETY: a NUL-terminated string of the host's.
            unsafe { CStr::from_ptr(why) }.to_string_lossy().into_owned()
        };
        return Err(format!("{}: {why}", path.display()));
    }
    let symbol = |name: &CStr| {
        // SAFETY: `lib` is an open library and `name` NUL-terminated.
        unsafe { libc::dlsym(lib, name.as_ptr()) }
    };
    let negotiate = symbol(c"vk_icdNegotiateLoaderICDInterfaceVersion");
    let gipa = symbol(c"vk_icdGetInstanceProcAddr");
    if negotiate.is_null() || gipa.is_null() {
        return Err(format!(
            "{}: not a Vulkan driver of loader interface 5 or later",
            path.display()
        ));
    }
    // SAFETY: the symbol is the driver's negotiation function, of this type
    // by the loader's interface.
    let negotiate: Negotiate = unsafe { std::mem::transmute(negotiate) };
    let mut interface = INTERFACE;
    // SAFETY: a valid out-parameter.
    let r = unsafe { negotiate(&mut interface) };
    if r != 0 || interface < 5 {
        return Err(format!(
            "{}: loader interface {interface} (result {r}); fwe needs 5 or later",
            path.display()
        ));
    }
    Ok(Driver {
        // SAFETY: the driver's `vk_icdGetInstanceProcAddr`, of this type by
        // the loader's interface.
        get_instance_proc_addr: unsafe { std::mem::transmute::<*mut c_void, GetProcAddr>(gipa) },
        interface,
        portability,
        manifest,
    })
}

/// The library a manifest names: a path relative to the manifest's
/// directory, an absolute path, or a bare name the dynamic linker finds,
/// as the loader takes it.
fn library_path(manifest: &Path, library: &str) -> PathBuf {
    let l = Path::new(library);
    if l.is_absolute() || !library.contains('/') {
        l.to_path_buf()
    } else {
        manifest.parent().unwrap_or(Path::new("/")).join(l)
    }
}

/// The string value of the first `"key"` in JSON text `text`.
fn json_string(text: &str, key: &str) -> Option<String> {
    let rest = json_value(text, key)?.strip_prefix('"')?;
    let mut out = String::new();
    let mut chars = rest.chars();
    loop {
        match chars.next()? {
            '"' => return Some(out),
            '\\' => match chars.next()? {
                'n' => out.push('\n'),
                't' => out.push('\t'),
                'u' => {
                    let hex: String = chars.by_ref().take(4).collect();
                    out.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
                }
                c => out.push(c),
            },
            c => out.push(c),
        }
    }
}

/// The boolean value of the first `"key"` in JSON text `text`.
fn json_bool(text: &str, key: &str) -> Option<bool> {
    let v = json_value(text, key)?;
    if v.starts_with("true") {
        Some(true)
    } else if v.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

/// The text from the first `"key"`'s value on.
fn json_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let quoted = format!("\"{key}\"");
    let at = text.find(&quoted)? + quoted.len();
    let rest = text[at..].trim_start().strip_prefix(':')?;
    Some(rest.trim_start())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_manifest_names_its_library_and_kind() {
        let m = r#"{
            "file_format_version": "1.0.0",
            "ICD": {
                "library_path": "../../../lib/libMolten\"VK\\.dylib",
                "api_version": "1.4.0",
                "is_portability_driver": true
            }
        }"#;
        assert_eq!(json_string(m, "library_path").unwrap(), "../../../lib/libMolten\"VK\\.dylib");
        assert_eq!(json_bool(m, "is_portability_driver"), Some(true));
        assert_eq!(json_bool(m, "absent"), None);
        assert_eq!(
            library_path(
                Path::new("/opt/homebrew/etc/vulkan/icd.d/M.json"),
                "../../../lib/l.dylib"
            ),
            PathBuf::from("/opt/homebrew/etc/vulkan/icd.d/../../../lib/l.dylib")
        );
        assert_eq!(
            library_path(Path::new("/a/m.json"), "libvulkan_x.dylib"),
            PathBuf::from("libvulkan_x.dylib")
        );
        assert_eq!(library_path(Path::new("/a/m.json"), "/b/l.dylib"), PathBuf::from("/b/l.dylib"));
    }
}
