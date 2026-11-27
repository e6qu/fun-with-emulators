//! Unit tests whose work changes what is the whole process's (the tables a
//! re-executed fwe loads, the file store's numbering), each run in a
//! process of its own: the test binary started again for that test alone,
//! so the tests running beside it in the test process keep theirs.

/// The environment variable naming the test a process runs alone.
const ALONE: &str = "FWE_UNIT_TEST_ALONE";

/// Whether this is the process test `name` of module `module` (as
/// `module_path!()` gives it) runs in alone, where its work is to be done.
/// Elsewhere the test binary is started again for that test alone, its
/// run checked to have passed, and the caller does nothing more.
pub fn in_own_process(module: &str, name: &str) -> bool {
    let path = format!("{}::{name}", module.split_once("::").map_or(module, |(_, rest)| rest));
    if std::env::var(ALONE).as_deref() == Ok(path.as_str()) {
        return true;
    }
    let exe = std::env::current_exe().expect("the test binary");
    let out = std::process::Command::new(exe)
        .args([path.as_str(), "--exact", "--test-threads=1"])
        .env(ALONE, &path)
        .stdin(std::process::Stdio::null())
        .output()
        .expect("the test binary runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("test result: ok. 1 passed"),
        "{path}, in a process of its own:\n{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    false
}
