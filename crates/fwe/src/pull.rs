//! `fwe --pull IMAGE DIR`: a root filesystem from a container image.
//!
//! The image's linux/arm64 variant is fetched from its registry (Docker
//! Hub unless the name says otherwise) over the registry's HTTP API, with
//! the host's `curl`, and each layer, checked against its SHA-256 digest,
//! is unpacked into `DIR` in order with the host's `tar`, its whiteouts
//! (`.wh.` entries) removing what earlier layers left. What an
//! unprivileged unpacking loses, owners other than root and set-ID bits or
//! modes that deny the owner, is kept as fwe keeps it for the guest
//! ([`fwe_kernel::owners`], [`fwe_kernel::modes`]), and every file is
//! given the user's own group, so that the guest sees root's. As a
//! container runtime does, it adds `/etc/resolv.conf` (the host's name
//! servers) and `/etc/hosts` where the image has none. The result is a
//! directory `fwe --root DIR` runs programs in.
//!
//! On a case-insensitive volume (macOS's default) two names that differ
//! only in case would become one file: the later of such files is left
//! out, and listed.

use crate::json::Json;
use crate::tarlist::{Entry, Kind};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

/// An image reference: `[registry/]repository[:tag][@digest]`.
#[derive(Debug, PartialEq, Eq)]
pub struct Reference {
    /// The registry's host (and port).
    pub registry: String,
    pub repository: String,
    /// The tag or digest to fetch.
    pub reference: String,
}

impl Reference {
    /// Parse `name` as Docker does: a first component with a `.` or `:`, or
    /// `localhost`, is a registry; otherwise the image is Docker Hub's, its
    /// official images under `library/`. No tag means `latest`.
    pub fn parse(name: &str) -> Result<Reference, String> {
        let bad = || format!("not an image name: {name}");
        let (rest, digest) = match name.split_once('@') {
            Some((r, d)) if d.starts_with("sha256:") && d.len() == 71 => (r, Some(d)),
            Some(_) => return Err(bad()),
            None => (name, None),
        };
        let (registry, path) = match rest.split_once('/') {
            Some((first, path))
                if first.contains('.') || first.contains(':') || first == "localhost" =>
            {
                (first.to_string(), path)
            }
            _ => ("docker.io".to_string(), rest),
        };
        let (path, tag) = match path.rsplit_once(':') {
            Some((p, t)) if !t.contains('/') => (p, Some(t)),
            _ => (path, None),
        };
        let valid = |s: &str| {
            !s.is_empty()
                && s.bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._-/".contains(&c))
        };
        if !valid(path) || tag.is_some_and(|t| t.is_empty() || t.len() > 128) {
            return Err(bad());
        }
        let docker_hub = registry == "docker.io";
        let repository = if docker_hub && !path.contains('/') {
            format!("library/{path}")
        } else {
            path.to_string()
        };
        Ok(Reference {
            registry: if docker_hub { "registry-1.docker.io".to_string() } else { registry },
            repository,
            reference: digest.or(tag).unwrap_or("latest").to_string(),
        })
    }
}

/// The manifest kinds asked for: an index of platforms, or one image's.
const INDEX_TYPES: [&str; 2] = [
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
];
const MANIFEST_TYPES: [&str; 2] = [
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
];

/// Fetch `image` and unpack it into `dir`, which must not exist or be
/// empty. Progress goes to standard error.
pub fn pull(image: &str, dir: &Path) -> Result<(), String> {
    let r = Reference::parse(image)?;
    if std::fs::read_dir(dir).is_ok_and(|mut d| d.next().is_some()) {
        return Err(format!("{} is not empty", dir.display()));
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    // Downloads beside the root, on its volume, removed when done.
    let mut work = dir.as_os_str().to_owned();
    work.push(".fwe-pull");
    let work = PathBuf::from(work);
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).map_err(|e| format!("{}: {e}", work.display()))?;
    let result = pull_into(&r, dir, &work);
    let _ = std::fs::remove_dir_all(&work);
    result
}

fn pull_into(r: &Reference, dir: &Path, work: &Path) -> Result<(), String> {
    eprintln!("fwe: pulling {}/{}:{} for linux/arm64", r.registry, r.repository, r.reference);
    let mut http = Registry { r, token: None, work };
    let accept: Vec<&str> = INDEX_TYPES.iter().chain(&MANIFEST_TYPES).copied().collect();
    let mut manifest = http.json(&format!("manifests/{}", r.reference), &accept)?;
    if manifest.get("manifests").is_some() {
        let digest = choose_platform(&manifest)?;
        manifest = http.json(&format!("manifests/{digest}"), &MANIFEST_TYPES)?;
    }
    // The image's own platform, where it was not chosen from an index.
    if let Some(digest) = manifest.get("config").and_then(|c| c.get("digest")).and_then(Json::str) {
        let path = http.blob(digest)?;
        let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let config = Json::parse(&text)?;
        let arch = config.get("architecture").and_then(Json::str).unwrap_or("");
        let os = config.get("os").and_then(Json::str).unwrap_or("");
        if (os, arch) != ("linux", "arm64") {
            return Err(format!("the image is for {os}/{arch}, not linux/arm64"));
        }
    }
    let layers = manifest.get("layers").map(Json::arr).unwrap_or_default();
    if layers.is_empty() {
        return Err("the image has no layers".to_string());
    }
    let mut files = Vec::new();
    for layer in layers {
        let digest = layer.get("digest").and_then(Json::str).ok_or("a layer without a digest")?;
        let path = http.blob(digest)?;
        let entries = crate::tarlist::read(&path)?;
        if let Some(e) = entries
            .iter()
            .find(|e| Path::new(&e.path).components().any(|c| !matches!(c, Component::Normal(_))))
        {
            return Err(format!("a layer names a path outside the root: {}", e.path));
        }
        files.push((path, entries));
    }
    let left_out = if case_sensitive(dir) {
        Vec::new()
    } else {
        case_collisions(files.iter().flat_map(|(_, e)| e))
    };
    let exclude = work.join("left-out");
    let patterns: String = left_out.iter().map(|(_, e)| format!("{}\n", glob_escape(e))).collect();
    std::fs::write(&exclude, patterns).map_err(|e| e.to_string())?;
    let skipped: std::collections::HashSet<&str> =
        left_out.iter().map(|(_, e)| e.as_str()).collect();
    for (path, entries) in &files {
        apply_whiteouts(dir, entries)?;
        unpack(path, dir, &exclude)?;
        keep_metadata(dir, entries, &skipped)?;
    }
    runtime_files(dir, &std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default())?;
    if !left_out.is_empty() {
        eprintln!(
            "fwe: {} is on a case-insensitive volume, where these files of the image would \
             replace another of the same name but for case; left out:",
            dir.display()
        );
        for (kept, e) in &left_out {
            eprintln!("  /{e} (kept /{kept})");
        }
        eprintln!(
            "fwe: for all of them, pull onto a case-sensitive APFS volume (Disk Utility, or \
             `hdiutil create -size 20g -fs 'Case-sensitive APFS' -volname linux -type SPARSE \
             linux.sparseimage` and `hdiutil attach linux.sparseimage`)"
        );
    }
    eprintln!("fwe: unpacked into {}", dir.display());
    Ok(())
}

/// `path` as a `tar` pattern that matches only itself.
fn glob_escape(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for c in path.chars() {
        if matches!(c, '*' | '?' | '[' | ']' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// What a container runtime gives a container at its start, where the
/// image has none: `/etc/resolv.conf`, with the host's name servers (from
/// `host_resolv`, the host's own file), and `/etc/hosts` for `localhost`.
fn runtime_files(dir: &Path, host_resolv: &str) -> Result<(), String> {
    let etc = dir.join("etc");
    std::fs::create_dir_all(&etc).map_err(|e| format!("{}: {e}", etc.display()))?;
    let resolv: String = host_resolv
        .lines()
        .filter(|l| ["nameserver", "search", "domain", "options"].iter().any(|k| l.starts_with(k)))
        .map(|l| format!("{l}\n"))
        .collect();
    let files = [
        ("resolv.conf", resolv),
        ("hosts", "127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n".to_string()),
    ];
    for (name, text) in files {
        let path = etc.join(name);
        // Not where the image has one, even a link (Debian's may be one).
        if std::fs::symlink_metadata(&path).is_err() {
            std::fs::write(&path, text).map_err(|e| format!("{}: {e}", path.display()))?;
        }
    }
    Ok(())
}

/// The digest of the linux/arm64 image an index lists.
fn choose_platform(index: &Json) -> Result<String, String> {
    let mut seen = Vec::new();
    for m in index.get("manifests").map(Json::arr).unwrap_or_default() {
        let p = m.get("platform");
        let field = |k| p.and_then(|p| p.get(k)).and_then(Json::str).unwrap_or("");
        if field("os") == "linux"
            && field("architecture") == "arm64"
            && matches!(field("variant"), "" | "v8")
            && let Some(d) = m.get("digest").and_then(Json::str)
        {
            return Ok(d.to_string());
        }
        if !field("os").is_empty() && field("os") != "unknown" {
            seen.push(format!("{}/{}", field("os"), field("architecture")));
        }
    }
    Err(format!("the image has no linux/arm64 variant (it has {})", seen.join(", ")))
}

/// The registry of one reference, with the token it gave, if any.
struct Registry<'a> {
    r: &'a Reference,
    token: Option<String>,
    work: &'a Path,
}

impl Registry<'_> {
    fn url(&self, path: &str) -> String {
        format!("https://{}/v2/{}/{path}", self.r.registry, self.r.repository)
    }

    /// The JSON document at `path` (under the repository).
    fn json(&mut self, path: &str, accept: &[&str]) -> Result<Json, String> {
        let out = self.work.join("document");
        self.get(&self.url(path), accept, &out)?;
        let text = std::fs::read_to_string(&out).map_err(|e| e.to_string())?;
        Json::parse(&text)
    }

    /// The blob `digest`, downloaded and checked against it.
    fn blob(&mut self, digest: &str) -> Result<PathBuf, String> {
        let hex = digest
            .strip_prefix("sha256:")
            .filter(|h| h.len() == 64 && h.bytes().all(|c| c.is_ascii_hexdigit()))
            .ok_or_else(|| format!("unsupported digest {digest}"))?;
        let out = self.work.join(hex);
        self.get(&self.url(&format!("blobs/{digest}")), &[], &out)?;
        let size = std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0);
        if sha256(&out)? != hex {
            return Err(format!("{digest}: the download does not match its digest"));
        }
        eprintln!("fwe: {digest} ({:.1} MB)", size as f64 / 1e6);
        Ok(out)
    }

    /// GET `url` into `out`: with the registry's token once it asks for
    /// one, following redirects (to a blob store, which is sent no token).
    fn get(&mut self, url: &str, accept: &[&str], out: &Path) -> Result<(), String> {
        let mut url = url.to_string();
        let mut asked = false;
        for _ in 0..8 {
            let ours = host_of(&url) == Some(self.r.registry.as_str());
            let token = if ours { self.token.as_deref() } else { None };
            let (code, headers) = curl(&url, accept, token, out, self.work)?;
            match code {
                200 => return Ok(()),
                301 | 302 | 303 | 307 | 308 => {
                    let to = header(&headers, "location").ok_or("a redirect with no location")?;
                    url = if to.starts_with('/') {
                        format!("https://{}{to}", host_of(&url).unwrap_or_default())
                    } else {
                        to
                    };
                }
                401 if ours && !asked => {
                    asked = true;
                    let challenge = header(&headers, "www-authenticate").unwrap_or_default();
                    self.token = Some(self.fetch_token(&challenge)?);
                }
                _ => {
                    let body = std::fs::read(out).unwrap_or_default();
                    let body = String::from_utf8_lossy(&body[..body.len().min(300)]).into_owned();
                    return Err(format!("{url}: HTTP {code}: {}", body.trim()));
                }
            }
        }
        Err(format!("{url}: too many redirects"))
    }

    /// An anonymous pull token, as the registry's `Bearer` challenge says
    /// where to get one.
    fn fetch_token(&mut self, challenge: &str) -> Result<String, String> {
        let params = challenge
            .strip_prefix("Bearer ")
            .ok_or_else(|| format!("the registry asks for {challenge:?}, not a token"))?;
        let field = |k: &str| {
            params.split(',').find_map(|kv| {
                let (key, v) = kv.trim().split_once('=')?;
                (key == k).then(|| v.trim_matches('"').to_string())
            })
        };
        let realm = field("realm").ok_or("a token challenge with no realm")?;
        let mut url = format!("{realm}?");
        if let Some(s) = field("service") {
            url.push_str(&format!("service={}&", encode(&s)));
        }
        let scope = format!("repository:{}:pull", self.r.repository);
        url.push_str(&format!("scope={}", encode(&field("scope").unwrap_or(scope))));
        let out = self.work.join("token");
        let (code, _) = curl(&url, &[], None, &out, self.work)?;
        let text = std::fs::read_to_string(&out).unwrap_or_default();
        if code != 200 {
            return Err(format!("{realm}: HTTP {code}: {}", text.trim()));
        }
        let t = Json::parse(&text)?;
        t.get("token")
            .or_else(|| t.get("access_token"))
            .and_then(Json::str)
            .map(str::to_string)
            .ok_or_else(|| "the registry gave no token".to_string())
    }
}

/// The host (and port) of an `https://` URL.
fn host_of(url: &str) -> Option<&str> {
    url.strip_prefix("https://")?.split('/').next()
}

/// `s` percent-encoded for a query string.
fn encode(s: &str) -> String {
    s.bytes()
        .map(|c| {
            if c.is_ascii_alphanumeric() || b"-_.~".contains(&c) {
                (c as char).to_string()
            } else {
                format!("%{c:02X}")
            }
        })
        .collect()
}

/// The value of the last `name` header in `headers` (a response's, or
/// several, as `curl -D` writes them).
fn header(headers: &str, name: &str) -> Option<String> {
    headers
        .lines()
        .filter_map(|l| l.split_once(':'))
        .filter(|(k, _)| k.trim().eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim().to_string())
        .next_back()
}

/// One request with the host's `curl`, no redirect followed: the status
/// and the response's headers, the body in `out`.
fn curl(
    url: &str,
    accept: &[&str],
    token: Option<&str>,
    out: &Path,
    work: &Path,
) -> Result<(u16, String), String> {
    let headers = work.join("headers");
    let mut cmd = Command::new("curl");
    cmd.args(["-sS", "--proto", "=https", "--retry", "3", "-o"]).arg(out).arg("-D").arg(&headers);
    cmd.args(["-w", "%{http_code}"]);
    if !accept.is_empty() {
        cmd.arg("-H").arg(format!("Accept: {}", accept.join(", ")));
    }
    if let Some(t) = token {
        cmd.arg("-H").arg(format!("Authorization: Bearer {t}"));
    }
    let r = cmd.arg(url).output().map_err(|e| format!("curl: {e}"))?;
    if !r.status.success() {
        return Err(format!("{url}: {}", String::from_utf8_lossy(&r.stderr).trim()));
    }
    let code = String::from_utf8_lossy(&r.stdout).trim().parse().unwrap_or(0);
    Ok((code, std::fs::read_to_string(&headers).unwrap_or_default()))
}

/// The SHA-256 of a file, in hex, by the host's `shasum`.
fn sha256(path: &Path) -> Result<String, String> {
    let r = Command::new("shasum")
        .args(["-a", "256"])
        .arg(path)
        .output()
        .map_err(|e| format!("shasum: {e}"))?;
    let out = String::from_utf8_lossy(&r.stdout);
    out.split_whitespace().next().map(str::to_string).ok_or_else(|| "shasum failed".to_string())
}

/// Whether names that differ only in case are different files on the
/// volume of `dir`.
#[cfg(target_os = "macos")]
fn case_sensitive(dir: &Path) -> bool {
    let Ok(c) = std::ffi::CString::new(dir.as_os_str().as_bytes()) else { return false };
    // SAFETY: a NUL-terminated path.
    unsafe { libc::pathconf(c.as_ptr(), libc::_PC_CASE_SENSITIVE) == 1 }
}

/// Other hosts' filesystems tell case apart.
#[cfg(not(target_os = "macos"))]
fn case_sensitive(_dir: &Path) -> bool {
    true
}

/// The files among `entries` (in the order the layers unpack them) that
/// would replace an earlier one on a volume where case does not count,
/// each with the one it would replace. Directories of such names merge,
/// and whiteouts remove, so neither is one.
fn case_collisions<'a>(entries: impl Iterator<Item = &'a Entry>) -> Vec<(String, String)> {
    let mut seen: std::collections::HashMap<String, &str> = std::collections::HashMap::new();
    let mut out = Vec::new();
    for e in entries {
        if e.kind == Kind::Dir || whiteout(&e.path).is_some() {
            continue;
        }
        let e = e.path.as_str();
        match seen.get(&e.to_lowercase()) {
            Some(&first) if first != e => out.push((first.to_string(), e.to_string())),
            Some(_) => {}
            None => {
                seen.insert(e.to_lowercase(), e);
            }
        }
    }
    out
}

/// What a whiteout entry removes: `Some(None)` for an opaque directory's
/// marker (everything in it from earlier layers), `Some(Some(name))` for a
/// removed path.
fn whiteout(entry: &str) -> Option<Option<String>> {
    let (parent, base) = match entry.rsplit_once('/') {
        Some((p, b)) => (Some(p), b),
        None => (None, entry),
    };
    let name = base.strip_prefix(".wh.")?;
    if name == ".wh..opq" {
        return Some(None);
    }
    Some(Some(match parent {
        Some(p) => format!("{p}/{name}"),
        None => name.to_string(),
    }))
}

/// Remove from `dir` what a layer's whiteouts remove of earlier layers.
fn apply_whiteouts(dir: &Path, entries: &[Entry]) -> Result<(), String> {
    for e in entries {
        let e = &e.path;
        let target = match whiteout(e) {
            None => continue,
            Some(Some(name)) => vec![dir.join(name)],
            Some(None) => {
                let parent = dir.join(Path::new(e).parent().unwrap_or(Path::new("")));
                match std::fs::read_dir(&parent) {
                    Ok(d) => d.filter_map(|x| x.ok().map(|x| x.path())).collect(),
                    Err(_) => continue,
                }
            }
        };
        for t in target {
            let r = match std::fs::symlink_metadata(&t) {
                Ok(m) if m.is_dir() => std::fs::remove_dir_all(&t),
                Ok(_) => std::fs::remove_file(&t),
                Err(_) => continue,
            };
            r.map_err(|err| format!("{}: {err}", t.display()))?;
        }
    }
    Ok(())
}

/// Unpack a layer into `dir`, with its files' extended attributes (file
/// capabilities among them), its whiteout entries left out, and the
/// paths `exclude` lists.
fn unpack(layer: &Path, dir: &Path, exclude: &Path) -> Result<(), String> {
    let r = Command::new("tar")
        .args(["--xattrs", "-xpf"])
        .arg(layer)
        .args(["--exclude", ".wh.*", "--exclude", "*/.wh.*", "-X"])
        .arg(exclude)
        .arg("-C")
        .arg(dir)
        .output()
        .map_err(|e| format!("tar: {e}"))?;
    if !r.status.success() {
        return Err(format!(
            "unpacking {}: {}",
            layer.file_name().map(OsStr::to_string_lossy).unwrap_or_default(),
            String::from_utf8_lossy(&r.stderr).trim()
        ));
    }
    Ok(())
}

/// After a layer is unpacked into `dir`: give each of its `entries` (but
/// those `skipped`) the user's own group, and keep what the host could not
/// set: an owner other than root, and a mode with set-ID bits or one that
/// denies the owner.
fn keep_metadata(
    dir: &Path,
    entries: &[Entry],
    skipped: &std::collections::HashSet<&str>,
) -> Result<(), String> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    // SAFETY: plain host call.
    let group = unsafe { libc::getegid() };
    // The directory of the entries last seen: a layer lists a directory's
    // entries together.
    let mut parent: Option<(String, OwnedFd)> = None;
    for e in entries {
        if e.kind == Kind::Other || whiteout(&e.path).is_some() || skipped.contains(e.path.as_str())
        {
            continue;
        }
        let (p, name) = e.path.rsplit_once('/').unwrap_or(("", &e.path));
        if parent.as_ref().is_none_or(|(at, _)| at != p) {
            let path = std::ffi::CString::new(dir.join(p).as_os_str().as_bytes())
                .map_err(|_| format!("a path with a NUL: {}", e.path))?;
            // SAFETY: a NUL-terminated path; the descriptor is owned below.
            let fd = unsafe {
                libc::open(
                    path.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(format!(
                    "{}: {}",
                    dir.join(p).display(),
                    std::io::Error::last_os_error()
                ));
            }
            // SAFETY: a descriptor just opened, owned here.
            parent = Some((p.to_string(), unsafe { OwnedFd::from_raw_fd(fd) }));
        }
        let fd = parent.as_ref().map(|(_, f)| f.as_raw_fd()).unwrap_or(-1);
        let cname =
            std::ffi::CString::new(name).map_err(|_| format!("a path with a NUL: {}", e.path))?;
        let fail = |what: &str, errno: i32| format!("{} ({what}): Linux errno {errno}", e.path);
        // SAFETY: zeroed bytes are a valid `stat`; `fstatat` fills it.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a live directory, a NUL-terminated name, an out-parameter.
        if unsafe { libc::fstatat(fd, cname.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
            let err = std::io::Error::last_os_error();
            // Not made: an AppleDouble entry (`._name`) the host's `tar`
            // turns into the attributes of `name`.
            if err.kind() == std::io::ErrorKind::NotFound {
                continue;
            }
            return Err(format!("{}: {err}", e.path));
        }
        if st.st_gid != group {
            // SAFETY: as above; only the group changes, to one of the user's.
            let r = unsafe {
                libc::fchownat(fd, cname.as_ptr(), u32::MAX, group, libc::AT_SYMLINK_NOFOLLOW)
            };
            if r != 0 {
                return Err(format!("{}: {}", e.path, std::io::Error::last_os_error()));
            }
        }
        if e.kind != Kind::Symlink
            && fwe_kernel::modes::host_perm(e.mode, e.kind == Kind::Dir) != e.mode
        {
            fwe_kernel::modes::keep_at(fd, &cname, e.mode).map_err(|n| fail("mode", n))?;
        }
        if (e.uid, e.gid) != (0, 0) {
            fwe_kernel::owners::keep_at(fd, &cname, (e.uid, e.gid))
                .map_err(|n| fail("owner", n))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(registry: &str, repository: &str, reference: &str) -> Reference {
        Reference {
            registry: registry.to_string(),
            repository: repository.to_string(),
            reference: reference.to_string(),
        }
    }

    #[test]
    fn names_are_read_as_docker_reads_them() {
        let hub = "registry-1.docker.io";
        assert_eq!(Reference::parse("alpine").unwrap(), r(hub, "library/alpine", "latest"));
        assert_eq!(Reference::parse("debian:trixie").unwrap(), r(hub, "library/debian", "trixie"));
        assert_eq!(
            Reference::parse("docker.io/library/alpine:3.24").unwrap(),
            r(hub, "library/alpine", "3.24")
        );
        assert_eq!(Reference::parse("someone/tool:1").unwrap(), r(hub, "someone/tool", "1"));
        assert_eq!(
            Reference::parse("ghcr.io/owner/img:v2").unwrap(),
            r("ghcr.io", "owner/img", "v2")
        );
        assert_eq!(
            Reference::parse("localhost:5000/img").unwrap(),
            r("localhost:5000", "img", "latest")
        );
        let digest = format!("sha256:{}", "a".repeat(64));
        assert_eq!(
            Reference::parse(&format!("alpine@{digest}")).unwrap(),
            r(hub, "library/alpine", &digest)
        );
        for bad in ["", "Alpine", "alpine:", "alpine@sha256:12", "a b"] {
            assert!(Reference::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_arm64_variant_is_chosen() {
        let index = Json::parse(
            r#"{"manifests": [
                {"digest": "sha256:amd", "platform": {"os": "linux", "architecture": "amd64"}},
                {"digest": "sha256:v7", "platform": {"os": "linux", "architecture": "arm", "variant": "v7"}},
                {"digest": "sha256:arm", "platform": {"os": "linux", "architecture": "arm64", "variant": "v8"}},
                {"digest": "sha256:att", "platform": {"os": "unknown", "architecture": "unknown"}}
            ]}"#,
        )
        .unwrap();
        assert_eq!(choose_platform(&index).unwrap(), "sha256:arm");
        let none = Json::parse(
            r#"{"manifests": [{"digest": "sha256:amd", "platform": {"os": "linux", "architecture": "amd64"}}]}"#,
        )
        .unwrap();
        assert!(choose_platform(&none).unwrap_err().contains("linux/amd64"));
    }

    #[test]
    fn headers_and_challenges_are_read() {
        let h = "HTTP/1.1 401 Unauthorized\r\nWww-Authenticate: Bearer realm=\"https://auth.example/token\",service=\"reg\"\r\n\r\n";
        assert_eq!(
            header(h, "www-authenticate").as_deref(),
            Some("Bearer realm=\"https://auth.example/token\",service=\"reg\"")
        );
        assert_eq!(header(h, "location"), None);
        assert_eq!(host_of("https://reg.example:5000/v2/x"), Some("reg.example:5000"));
        assert_eq!(
            encode("repository:library/alpine:pull"),
            "repository%3Alibrary%2Falpine%3Apull"
        );
    }

    #[test]
    fn whiteouts_and_case_collisions_are_found() {
        assert_eq!(whiteout("etc/.wh.motd"), Some(Some("etc/motd".to_string())));
        assert_eq!(whiteout(".wh.tmp"), Some(Some("tmp".to_string())));
        assert_eq!(whiteout("var/cache/.wh..wh..opq"), Some(None));
        assert_eq!(whiteout("etc/motd"), None);
        let entry = |p: &str| Entry {
            path: p.trim_end_matches('/').to_string(),
            kind: if p.ends_with('/') { Kind::Dir } else { Kind::File },
            mode: 0o644,
            uid: 0,
            gid: 0,
        };
        let entries =
            ["lib/terminfo/E/", "lib/terminfo/e/", "lib/terminfo/x", "usr/.wh.Lib"].map(entry);
        assert!(case_collisions(entries.iter()).is_empty());
        let entries = ["usr/share/a/Make", "usr/share/a/make", "usr/share/a/MAKE", "b"].map(entry);
        assert_eq!(
            case_collisions(entries.iter()),
            [("usr/share/a/Make", "usr/share/a/make"), ("usr/share/a/Make", "usr/share/a/MAKE")]
                .map(|(a, b)| (a.to_string(), b.to_string()))
        );
        assert_eq!(glob_escape("a[1]*?.gz"), "a\\[1\\]\\*\\?.gz");
    }

    /// Two layers unpacked in order: the second's whiteouts remove a file
    /// and empty an opaque directory of the first, and are not unpacked
    /// themselves; a path asked to be left out is. (With the host's `tar`,
    /// macOS's: `fwe` runs only there.)
    #[cfg(target_os = "macos")]
    #[test]
    fn layers_apply_in_order_with_whiteouts() {
        let base = std::env::temp_dir().join(format!("fwe-pull-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let make_layer = |name: &str, files: &[&str]| {
            let src = base.join(format!("src-{name}"));
            for f in files {
                let p = src.join(f);
                std::fs::create_dir_all(p.parent().unwrap()).unwrap();
                std::fs::write(&p, f).unwrap();
            }
            let out = base.join(format!("{name}.tar.gz"));
            let ok = Command::new("tar")
                .arg("-czf")
                .arg(&out)
                .arg("-C")
                .arg(&src)
                .arg(".")
                .status()
                .unwrap()
                .success();
            assert!(ok);
            out
        };
        let one = make_layer("one", &["etc/motd", "etc/keep", "var/cache/a", "var/cache/b"]);
        let two = make_layer(
            "two",
            &["etc/.wh.motd", "var/cache/.wh..wh..opq", "var/cache/c", "usr/skip[1]", "usr/x"],
        );
        let root = base.join("root");
        std::fs::create_dir_all(&root).unwrap();
        let exclude = base.join("exclude");
        std::fs::write(&exclude, format!("{}\n", glob_escape("usr/skip[1]"))).unwrap();
        for layer in [&one, &two] {
            let entries = crate::tarlist::read(layer).unwrap();
            assert!(entries.iter().any(|e| e.path == "etc" && e.kind == Kind::Dir));
            apply_whiteouts(&root, &entries).unwrap();
            unpack(layer, &root, &exclude).unwrap();
        }
        let names = |d: &str| {
            let mut v: Vec<String> = std::fs::read_dir(root.join(d))
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            v.sort();
            v
        };
        assert_eq!(names("etc"), ["keep"]);
        assert_eq!(names("var/cache"), ["c"]);
        assert_eq!(names("usr"), ["x"]);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// A root without the files a runtime gives a container gets them; an
    /// image's own are kept.
    #[test]
    fn runtime_files_are_added_where_missing() {
        let base = std::env::temp_dir().join(format!("fwe-pull-etc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("etc")).unwrap();
        std::fs::write(base.join("etc/hosts"), "mine\n").unwrap();
        let host = "# a comment\nnameserver 10.0.0.1\nsearch example.org\nsortlist x\n";
        runtime_files(&base, host).unwrap();
        let read = |f: &str| std::fs::read_to_string(base.join(f)).unwrap();
        assert_eq!(read("etc/resolv.conf"), "nameserver 10.0.0.1\nsearch example.org\n");
        assert_eq!(read("etc/hosts"), "mine\n");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// What an unprivileged unpacking loses is kept as fwe keeps it: a
    /// set-ID mode, a mode that denies the owner, and an owner other than
    /// root.
    #[cfg(target_os = "macos")]
    #[test]
    fn owners_and_modes_are_kept() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!("fwe-pull-keep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let src = base.join("src");
        std::fs::create_dir_all(src.join("bin")).unwrap();
        std::fs::create_dir_all(src.join("home/u")).unwrap();
        for (f, mode) in [("bin/su", 0o4755), ("bin/plain", 0o755), ("home/u/secret", 0o440)] {
            std::fs::write(src.join(f), f).unwrap();
            std::fs::set_permissions(src.join(f), std::fs::Permissions::from_mode(mode)).unwrap();
        }
        let layer = base.join("layer.tar");
        let ok = Command::new("tar")
            .env("COPYFILE_DISABLE", "1")
            .args(["--uid", "7", "--gid", "8", "-cf"])
            .arg(&layer)
            .arg("-C")
            .arg(&src)
            .args(["bin", "home"])
            .status()
            .unwrap()
            .success();
        assert!(ok);
        let root = base.join("root");
        std::fs::create_dir_all(&root).unwrap();
        let entries = crate::tarlist::read(&layer).unwrap();
        let exclude = base.join("exclude");
        std::fs::write(&exclude, "").unwrap();
        unpack(&layer, &root, &exclude).unwrap();
        keep_metadata(&root, &entries, &Default::default()).unwrap();
        let at = |f: &str| {
            let path = std::ffi::CString::new(root.join(f).as_os_str().as_bytes()).unwrap();
            // SAFETY: zeroed bytes are a valid `stat`; `lstat` fills it.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: a NUL-terminated path and an out-parameter.
            assert_eq!(unsafe { libc::lstat(path.as_ptr(), &mut st) }, 0, "{f}");
            (path, st)
        };
        let (su, st) = at("bin/su");
        assert!(fwe_kernel::modes::kept_path(&su));
        assert_eq!(fwe_kernel::owners::of_path(&su, &st), (7, 8));
        // SAFETY: plain host call.
        assert_eq!(st.st_gid, unsafe { libc::getegid() });
        let (secret, _) = at("home/u/secret");
        assert!(fwe_kernel::modes::kept_path(&secret));
        let (plain, _) = at("bin/plain");
        assert!(!fwe_kernel::modes::kept_path(&plain));
        let _ = std::fs::remove_dir_all(&base);
    }
}
