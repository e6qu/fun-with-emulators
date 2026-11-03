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
  --root DIR   use DIR as the guest root filesystem
  --host-info  show host features that affect compatibility
  --probe NAME run one host-behaviour probe (diagnostic; used by CI)
  --hv-spike   run the hypervisor-backend feasibility spike (see
               docs/hypervisor-spike.md; Apple Silicon, needs the entitlement)
  -h, --help   show this help
  -V, --version
";

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1).peekable();
    let mut options = fwe_native::Options::default();
    while let Some(arg) = args.peek() {
        match arg.as_bytes() {
            b"--strace" => options.strace = true,
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
            b"--hv-spike" => {
                // Feasibility spike for the hypervisor backend; see
                // docs/hypervisor-spike.md. Not part of normal operation.
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
