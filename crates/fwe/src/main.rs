//! `fwe`: run a Linux arm64 executable on macOS.
//!
//! The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
//! "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
//! "OPTIONAL" in this crate's documentation and comments are to be
//! interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only
//! when, they appear in all capitals, as shown here.

#[cfg(target_os = "macos")]
mod alloc;

/// The mark that Objective-C classes' `+initialize` is safe in a fork child
/// of one of fwe's processes that had threads (objc4 reads it from the
/// executable: `hasForkOkSection`). The runtime otherwise refuses any such
/// `+initialize`, in case the fork came while one ran: it would refuse the
/// Mac's Vulkan driver in a program a threaded process's child starts in
/// place (Chromium's GPU process). No fork comes while one runs: fwe runs
/// Objective-C code only through the Mac's Vulkan driver, a child forked
/// while the driver was in its parent never calls into it, and its
/// `execve` starts a fresh process (`vulkan::device::driver_in_memory`).
#[cfg(target_os = "macos")]
#[used]
#[unsafe(link_section = "__DATA,__objc_fork_ok")]
static OBJC_FORK_OK: [u32; 1] = [1];

/// The Objective-C image information clang writes for each image with
/// Objective-C in it (version 0; flags: class properties in categories),
/// without which the runtime looks at no section of the executable,
/// [`OBJC_FORK_OK`] among them.
#[cfg(target_os = "macos")]
#[used]
#[unsafe(link_section = "__DATA,__objc_imageinfo,regular,no_dead_strip")]
static OBJC_IMAGE_INFO: [u32; 2] = [0, 64];
mod json;
mod pull;
mod tarlist;

use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "\
usage: fwe [options] <program> [args...]
       fwe --pull IMAGE DIR

Run a Linux arm64 executable, or make a root filesystem to run them in.

options:
  --strace     trace system calls to standard error
  --strace=failures
               trace only the calls that fail, and fwe's notes
  --strace-file=PATH
               trace to PATH (appended to) instead, every process of the
               run, each line naming its process
  --root DIR   use DIR as the guest root filesystem
  --pull IMAGE DIR
               fetch a container image's linux/arm64 variant (alpine,
               debian:trixie, ghcr.io/owner/name:tag...) and unpack it into
               DIR, a new or empty directory, for --root
  --host-info  show host features that affect compatibility
  --probe NAME run one host-behaviour probe (diagnostic; used by CI)
  --hv-spike   check that the hypervisor backend can run here: a tiny guest
               in a VM (see docs/hypervisor.md; Apple Silicon, needs the
               entitlement)
  --vm         run every program in the VM (the hypervisor backend), not
               only those linked below 4 GiB: for programs that need 4 KiB
               pages, such as Wine (goes first)
  --hv-standin run the hypervisor backend on a software stand-in for
               Hypervisor.framework instead of a real VM (for development
               and tests; needs Unicorn; goes first)
  --hv-record DEST
               record the hypervisor backend's VM calls, synchronously, to
               file:PATH and/or udp:HOST:PORT (comma separated; also
               FWE_HV_RECORD; goes first; see docs/hypervisor.md)
  -h, --help   show this help
  -V, --version
";

fn main() -> ExitCode {
    fwe_kernel::timing::init();
    fwe_native::install_kill_relay();
    fwe_native::remember_exe();
    let mut args: Vec<OsString> = std::env::args_os().skip(1).collect();
    // These come first, as fwe passes them on to every process it starts
    // for the guest.
    let mut record = std::env::var("FWE_HV_RECORD").ok().filter(|s| !s.is_empty());
    let mut vm = false;
    loop {
        match args.first().map(|a| a.as_bytes()) {
            Some(b"--hv-standin") => {
                args.remove(0);
                if !fwe_native::hv::use_standin() {
                    eprintln!("fwe: --hv-standin needs Apple Silicon macOS");
                    return ExitCode::from(2);
                }
            }
            Some(b"--vm") => {
                args.remove(0);
                vm = true;
            }
            Some(b"--hv-record") if args.len() > 1 => {
                args.remove(0);
                record = Some(args.remove(0).to_string_lossy().into_owned());
            }
            _ => break,
        }
    }
    // Once the stand-in, which can follow it, is known.
    if vm {
        if !fwe_native::hv::usable() {
            eprintln!(
                "fwe: --vm needs the hypervisor backend: fwe with the hypervisor \
                 entitlement on a Mac with hypervisor support, or --hv-standin"
            );
            return ExitCode::from(2);
        }
        fwe_native::hv::use_vm_always();
    }
    if let Some(spec) = record
        && let Err(e) = fwe_native::hv::start_recording(&spec)
    {
        eprintln!("fwe: --hv-record: {e}");
        return ExitCode::from(2);
    }
    if args.first().is_some_and(|a| a == "--hv-standin-watch") {
        // The stand-in's watcher of one VM process; not for direct use.
        fwe_native::hv::standin_watch(
            &args.get(1).map(|a| a.to_string_lossy()).unwrap_or_default(),
        );
    }
    if args.first().is_some_and(|a| a == "--hv-fork-child") {
        // A fork child of a VM process (see hv::fork); not for direct use.
        fwe_native::hv::fork_child();
    }
    // Anywhere else they would come too late: `--hv-spike --hv-standin`
    // would reach the real framework first.
    if let Some(late) = late_leading_option(&args) {
        eprintln!("fwe: {late} goes before the other options\n{USAGE}");
        return ExitCode::from(2);
    }
    let mut args = args.into_iter().peekable();
    let mut options = fwe_native::Options::default();
    // The host display, given by the fwe that re-executes this one.
    let mut host_display: Option<OsString> = None;
    while let Some(arg) = args.peek() {
        match arg.as_bytes() {
            b"--strace" => options.strace.enabled = true,
            b"--strace=failures" => {
                options.strace.enabled = true;
                options.strace.failures_only = true;
            }
            a if a.starts_with(b"--strace-file=") => {
                if let Err(e) = fwe_native::trace_to_file(&a[b"--strace-file=".len()..]) {
                    eprintln!("fwe: --strace-file: {e}");
                    return ExitCode::from(2);
                }
            }
            b"--root" => {
                args.next();
                match args.next() {
                    Some(dir) => options.root = Some(PathBuf::from(dir)),
                    None => {
                        eprintln!("fwe: --root needs a directory\n{USAGE}");
                        return ExitCode::from(2);
                    }
                }
                continue;
            }
            // Used when fwe re-executes itself for a guest execve.
            b"--guest-path" => options.guest_path = true,
            b"--cwd" | b"--argv0" | b"--comm" | b"--exec-state" | b"--exe-fd" | b"--exe-store"
            | b"--user-dir" | b"--host-display" => {
                let flag = args.next().unwrap();
                let Some(value) = args.next() else {
                    eprintln!("fwe: {} needs a value\n{USAGE}", flag.to_string_lossy());
                    return ExitCode::from(2);
                };
                if flag == "--host-display" {
                    host_display = Some(value);
                } else if flag == "--user-dir" {
                    fwe_native::adopt_user_dir(value.as_bytes());
                } else if flag == "--comm" {
                    options.comm = Some(value.as_bytes().to_vec());
                } else if flag == "--cwd" {
                    options.cwd = Some(value.as_bytes().to_vec());
                } else if flag == "--exec-state" {
                    options.exec_state = Some(value.as_bytes().to_vec());
                } else if flag == "--exe-fd" {
                    let Some(fd) = value.to_str().and_then(|v| v.parse().ok()) else {
                        eprintln!("fwe: --exe-fd needs a descriptor number\n{USAGE}");
                        return ExitCode::from(2);
                    };
                    options.exe_fd = Some(fd);
                } else if flag == "--exe-store" {
                    let Some(file) = value.to_str().and_then(fwe_native::parse_exe_store) else {
                        eprintln!("fwe: --exe-store needs a file of the store\n{USAGE}");
                        return ExitCode::from(2);
                    };
                    options.exe_store = Some(file);
                } else {
                    options.argv0 = Some(value);
                }
                continue;
            }
            b"-h" | b"--help" => {
                print!("{USAGE}");
                return ExitCode::SUCCESS;
            }
            b"--probe" => {
                args.next();
                let name = args.next().unwrap_or_default();
                return match fwe_native::probe(&name.to_string_lossy()) {
                    Ok(r) => {
                        println!("{r}");
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("fwe: {e}");
                        ExitCode::from(2)
                    }
                };
            }
            b"--pull" => {
                args.next();
                let (Some(image), Some(dir)) = (args.next(), args.next()) else {
                    eprintln!("fwe: --pull needs an image and a directory\n{USAGE}");
                    return ExitCode::from(2);
                };
                return match pull::pull(&image.to_string_lossy(), &PathBuf::from(dir)) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(e) => {
                        eprintln!("fwe: --pull: {e}");
                        ExitCode::FAILURE
                    }
                };
            }
            b"--host-info" => {
                println!("{}", fwe_native::host_support());
                return ExitCode::SUCCESS;
            }
            // The spike is the real framework's own check: it creates a VM
            // with no stand-in behind it.
            b"--hv-spike" if fwe_native::hv::standin_active() => {
                eprintln!("fwe: --hv-spike tests the real Hypervisor.framework, not the stand-in");
                return ExitCode::from(2);
            }
            b"--hv-spike" => {
                // A quick check that a VM runs here (docs/hypervisor.md).
                return match fwe_native::hv::spike() {
                    Ok(out) => {
                        use std::io::Write;
                        let _ = std::io::stdout().write_all(&out.stdout);
                        // The spike itself succeeded; the guest's own status is
                        // reported in text (it is 42 when the guest ran fully),
                        // so the process exits 0 for a clean CI assertion.
                        println!("fwe: hv spike guest exited with status {}", out.exit_code);
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("fwe: hv spike failed: {e}");
                        ExitCode::from(2)
                    }
                };
            }
            b"-V" | b"--version" => {
                println!("fwe {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            b"--" => {
                args.next();
                break;
            }
            a if a.starts_with(b"-") => {
                eprintln!("fwe: unknown option {}\n{USAGE}", arg.to_string_lossy());
                return ExitCode::from(2);
            }
            _ => break,
        }
        args.next();
    }
    let guest_args: Vec<OsString> = args.collect();
    let Some(program) = guest_args.first() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let path = PathBuf::from(program);
    // The host display: fwe's `DISPLAY`, or for an fwe re-executed on a
    // guest's program (whose environment is the guest's) the one given.
    let host = if options.guest_path { host_display } else { std::env::var_os("DISPLAY") };
    fwe_kernel::x11::set_host(host.as_ref().map(|v| v.as_bytes()));
    // The guest's environment is fwe's, but for the host display, which
    // the guest knows by its number ([`fwe_kernel::x11`]).
    let env: Vec<OsString> = std::env::vars_os()
        .map(|(k, v)| {
            use std::os::unix::ffi::{OsStrExt, OsStringExt};
            let v = if k == "DISPLAY" {
                OsString::from_vec(fwe_kernel::x11::guest_display(v.as_bytes()))
            } else {
                v
            };
            let mut kv = k;
            kv.push("=");
            kv.push(v);
            kv
        })
        .collect();

    let error = fwe_native::run(&path, &guest_args, &env, &options);
    eprintln!("fwe: {}: {error}", path.display());
    // The shell's "cannot execute" status.
    ExitCode::from(126)
}

/// `--vm`, `--hv-standin` or `--hv-record` among fwe's own options after the first
/// position (the guest's arguments, after its program, are not looked at).
fn late_leading_option(args: &[OsString]) -> Option<String> {
    let mut i = 0;
    while let Some(a) = args.get(i) {
        match a.as_bytes() {
            b"--vm" | b"--hv-standin" | b"--hv-record" => {
                return Some(a.to_string_lossy().into_owned());
            }
            b"--root" | b"--cwd" | b"--argv0" | b"--comm" | b"--exec-state" | b"--exe-fd"
            | b"--exe-store" | b"--probe" | b"--host-display" => i += 2,
            b"--" => return None,
            o if o.starts_with(b"-") => i += 1,
            _ => return None,
        }
    }
    None
}

#[cfg(target_os = "macos")]
#[global_allocator]
static ALLOCATOR: alloc::Allocator = alloc::Allocator;
