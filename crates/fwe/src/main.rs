//! `fwe`: run a Linux arm64 executable on macOS.

use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "\
usage: fwe [options] <program> [args...]

Run a Linux arm64 executable.

options:
  --strace     trace system calls to standard error
  --strace=failures
               trace only the calls that fail, and fwe's notes
  --strace-file=PATH
               trace to PATH (appended to) instead, every process of the
               run, each line naming its process
  --root DIR   use DIR as the guest root filesystem
  --host-info  show host features that affect compatibility
  --probe NAME run one host-behaviour probe (diagnostic; used by CI)
  --hv-spike   check that the hypervisor backend can run here: a tiny guest
               in a VM (see docs/hypervisor.md; Apple Silicon, needs the
               entitlement)
  --vm         run every program in the VM (the hypervisor backend), not
               only those linked below 4 GiB: for programs that need 4 KiB
               pages, such as Wine (must come first)
  --hv-standin run the hypervisor backend on a software stand-in for
               Hypervisor.framework instead of a real VM (for development
               and tests; needs Unicorn; must come first)
  --hv-record DEST
               record the hypervisor backend's VM calls, synchronously, to
               file:PATH and/or udp:HOST:PORT (comma separated; also
               FWE_HV_RECORD; must come first; see docs/hypervisor.md)
  -h, --help   show this help
  -V, --version
";

fn main() -> ExitCode {
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
    // Once the stand-in, which may follow it, is known.
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
    if let Some(spec) = record {
        if let Err(e) = fwe_native::hv::start_recording(&spec) {
            eprintln!("fwe: --hv-record: {e}");
            return ExitCode::from(2);
        }
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
        eprintln!("fwe: {late} must come first\n{USAGE}");
        return ExitCode::from(2);
    }
    let mut args = args.into_iter().peekable();
    let mut options = fwe_native::Options::default();
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
            b"--cwd" | b"--argv0" | b"--exec-state" | b"--exe-fd" => {
                let flag = args.next().unwrap();
                let Some(value) = args.next() else {
                    eprintln!("fwe: {} needs a value\n{USAGE}", flag.to_string_lossy());
                    return ExitCode::from(2);
                };
                if flag == "--cwd" {
                    options.cwd = Some(value.as_bytes().to_vec());
                } else if flag == "--exec-state" {
                    options.exec_state = Some(value.as_bytes().to_vec());
                } else if flag == "--exe-fd" {
                    let Some(fd) = value.to_str().and_then(|v| v.parse().ok()) else {
                        eprintln!("fwe: --exe-fd needs a descriptor number\n{USAGE}");
                        return ExitCode::from(2);
                    };
                    options.exe_fd = Some(fd);
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
    let env: Vec<OsString> = std::env::vars_os()
        .map(|(k, v)| {
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
            b"--root" | b"--cwd" | b"--argv0" | b"--exec-state" | b"--exe-fd" | b"--probe" => {
                i += 2
            }
            b"--" => return None,
            o if o.starts_with(b"-") => i += 1,
            _ => return None,
        }
    }
    None
}
