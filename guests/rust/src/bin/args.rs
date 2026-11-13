//! Prints its arguments and selected environment variables, then exits with
//! the status given by an `exit=N` argument. With a `cwd` argument, also its
//! working directory and whether `./args` is found from it.
//!
//! `args script DIR` (or `args memfd-script`) runs itself again through a
//! script, `#!` naming it with one argument, made in DIR (or in a memfd,
//! run through its descriptor, as `fexecve` does): with no shell between,
//! the kernel runs the interpreter.

unsafe extern "C" {
    fn execv(path: *const std::ffi::c_char, argv: *const *const std::ffi::c_char) -> i32;
    fn syscall(nr: i64, ...) -> i64;
}

/// Run the script `text` from `path` (or, with `None`, from a memfd) with
/// argument `one`.
fn run_script(text: &str, path: Option<&str>) -> ! {
    use std::ffi::CString;
    let argv0 = CString::new("script").unwrap();
    let one = CString::new("one").unwrap();
    let argv = [argv0.as_ptr(), one.as_ptr(), std::ptr::null()];
    match path {
        Some(p) => {
            std::fs::write(p, text).unwrap();
            std::fs::set_permissions(p, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
            let c = CString::new(p).unwrap();
            // SAFETY: a NUL-terminated path and argument array.
            unsafe { execv(c.as_ptr(), argv.as_ptr()) };
        }
        None => {
            let env: [*const std::ffi::c_char; 1] = [std::ptr::null()];
            // SAFETY: memfd_create, write and execveat with valid arguments.
            unsafe {
                let fd = syscall(279, c"script".as_ptr(), 0i64);
                syscall(64, fd, text.as_ptr(), text.len());
                syscall(281, fd, c"".as_ptr(), argv.as_ptr(), env.as_ptr(), 0x1000i64);
            }
        }
    }
    println!("exec failed: {}", std::io::Error::last_os_error());
    std::process::exit(1);
}

fn main() {
    let all: Vec<String> = std::env::args().collect();
    if all.len() >= 2 && (all[1] == "script" || all[1] == "memfd-script") {
        let me = std::fs::read_link("/proc/self/exe").unwrap();
        let text = format!("#!{} -a\nnot read\n", me.display());
        let path = (all[1] == "script").then(|| format!("{}/script.sh", all[2]));
        run_script(&text, path.as_deref());
    }
    let mut status = 0;
    for (i, arg) in std::env::args().enumerate() {
        println!("arg[{i}]={arg}");
        if let Some(n) = arg.strip_prefix("exit=") {
            status = n.parse().expect("exit status");
        }
        if arg == "cwd" {
            println!("cwd={}", std::env::current_dir().unwrap().display());
            println!("./args found: {}", std::path::Path::new("./args").exists());
        }
    }
    match std::env::var("FWE_GUEST_VAR") {
        Ok(v) => println!("FWE_GUEST_VAR={v}"),
        Err(_) => println!("FWE_GUEST_VAR unset"),
    }
    std::process::exit(status);
}
