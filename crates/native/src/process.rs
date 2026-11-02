//! Process system calls for the native backend: `execve`, `fork` and `wait`.

use crate::{KERNEL, NativePlatform, load_image, page_size, thread_pointer_slot, trap};
use fwe_abi::{err, errno};
use fwe_kernel::Regs;

/// Read a NUL-terminated string from guest memory.
///
/// # Safety
/// `addr` points to a NUL-terminated string in guest memory.
unsafe fn read_cstr(addr: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut p = addr;
    loop {
        // SAFETY: the caller guarantees a NUL-terminated string.
        let b = unsafe { (p as *const u8).read() };
        if b == 0 {
            return out;
        }
        out.push(b);
        p += 1;
    }
}

/// Read a NULL-terminated array of string pointers (`argv`/`envp`).
///
/// # Safety
/// `addr` points to a NULL-terminated array of pointers, each to a C string.
unsafe fn read_cstr_array(addr: u64) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if addr == 0 {
        return out;
    }
    let mut p = addr;
    loop {
        // SAFETY: the caller guarantees a NULL-terminated pointer array.
        let ptr = unsafe { (p as *const u64).read() };
        if ptr == 0 {
            return out;
        }
        // SAFETY: each non-null entry points to a C string.
        out.push(unsafe { read_cstr(ptr) });
        p += 8;
    }
}

/// `execve(path, argv, envp)`: replace the current program image with a new
/// one and start it. Returns a negative errno on failure; on success it does
/// not return (it enters the new program).
///
/// The old image's mappings are not reclaimed (full address-space teardown
/// needs mapping tracking), so this suits the common fork-then-exec and
/// exec-chain cases. `execve` in a process with other live threads is not
/// supported yet.
pub fn do_execve(regs: &Regs) -> i64 {
    // SAFETY: the guest passed a path and argv/envp pointers.
    let (path, args, env) =
        unsafe { (read_cstr(regs.x[0]), read_cstr_array(regs.x[1]), read_cstr_array(regs.x[2])) };

    let mut guard = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
    let k = guard.as_mut().unwrap();
    let page = page_size();
    let strace = k.tracer.enabled;
    let platform = NativePlatform { tp_slot: thread_pointer_slot(), page_size: page };
    let fs = k.fs.as_ref().expect("filesystem configured");

    let file = match fs.read(&path) {
        Ok(f) => f,
        Err(e) => return err(e),
    };
    let arg_refs: Vec<&[u8]> = args.iter().map(Vec::as_slice).collect();
    let env_refs: Vec<&[u8]> = env.iter().map(Vec::as_slice).collect();
    let out = match load_image(&file, &path, &arg_refs, &env_refs, fs, &platform, page, strace) {
        Ok(out) => out,
        // The old image is untouched on failure, so the guest can handle the
        // error; report it as "not an executable".
        Err(_) => return err(errno::ENOEXEC),
    };

    k.exec_reset();
    k.brk = out.brk;
    let (sp, entry) = (out.sp, out.entry);
    drop(guard);

    // Enter the new program with a fresh register state.
    trap::enter_guest(sp, entry)
}
