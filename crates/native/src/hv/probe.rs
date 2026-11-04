//! `fwe --probe hv-map-rules`: which host memory `hv_vm_map` takes, asked of
//! the framework itself — or, under `--hv-standin`, of the stand-in, whose
//! rule is inferred from what the framework did (see [`super::standin`]).
//! The self-hosted `hypervisor` CI job runs both and fails if they differ.
//!
//! It creates a VM, so on the real framework it is for a machine meant for
//! VM runs only. The VM has no vCPU and is destroyed before the probe
//! returns, whatever happens.

use super::ffi::*;

type Port = u32;

const VM_PROT_READ: i32 = 1;
const VM_PROT_WRITE: i32 = 2;
const VM_PROT_EXECUTE: i32 = 4;
const VM_FLAGS_ANYWHERE: i32 = 1;
const MAP_MEM_VM_SHARE: i32 = 0x40_0000;
const VM_INHERIT_COPY: u32 = 1;

unsafe extern "C" {
    static mach_task_self_: Port;
    fn mach_vm_allocate(task: Port, addr: *mut u64, size: u64, flags: i32) -> i32;
    fn mach_vm_protect(task: Port, addr: u64, size: u64, set_max: i32, prot: i32) -> i32;
    fn mach_vm_deallocate(task: Port, addr: u64, size: u64) -> i32;
    fn mach_make_memory_entry_64(
        task: Port,
        size: *mut u64,
        offset: u64,
        permission: i32,
        entry: *mut Port,
        parent: Port,
    ) -> i32;
    fn mach_vm_map(
        task: Port,
        addr: *mut u64,
        size: u64,
        mask: u64,
        flags: i32,
        object: Port,
        offset: u64,
        copy: i32,
        cur: i32,
        max: i32,
        inherit: u32,
    ) -> i32;
    fn mach_port_deallocate(task: Port, name: Port) -> i32;
}

const SIZE: u64 = 16 << 10;

/// Host memory of one kind, for one case.
struct Host {
    addr: u64,
    /// Freed when the case is done (`false` for memory already gone).
    owned: bool,
}

fn task() -> Port {
    // SAFETY: reading the task port the runtime initialized.
    unsafe { mach_task_self_ }
}

/// Fresh memory with protections `cur` and at most `max`.
fn allocate(cur: i32, max: i32) -> Result<Host, String> {
    let mut addr = 0;
    // SAFETY: allocating and protecting fresh memory of our own.
    unsafe {
        if mach_vm_allocate(task(), &mut addr, SIZE, VM_FLAGS_ANYWHERE) != 0 {
            return Err("mach_vm_allocate failed".into());
        }
        mach_vm_protect(task(), addr, SIZE, 1, max);
        mach_vm_protect(task(), addr, SIZE, 0, cur);
    }
    Ok(Host { addr, owned: true })
}

/// A shared memory entry of read-only memory, mapped at most readable: what
/// a `vfork` child was given for the parent's code before the fix.
fn shared_read_only() -> Result<Host, String> {
    let src =
        allocate(VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE)?;
    // SAFETY: Mach calls on memory and a port of our own.
    unsafe {
        mach_vm_protect(task(), src.addr, SIZE, 0, VM_PROT_READ);
        let mut size = SIZE;
        let mut entry = 0;
        let kr = mach_make_memory_entry_64(
            task(),
            &mut size,
            src.addr,
            MAP_MEM_VM_SHARE | VM_PROT_READ,
            &mut entry,
            0,
        );
        if kr != 0 {
            return Err(format!("mach_make_memory_entry_64 failed ({kr:#x})"));
        }
        let mut addr = 0;
        let kr = mach_vm_map(
            task(),
            &mut addr,
            SIZE,
            0,
            VM_FLAGS_ANYWHERE,
            entry,
            0,
            0,
            VM_PROT_READ,
            VM_PROT_READ,
            VM_INHERIT_COPY,
        );
        mach_port_deallocate(task(), entry);
        mach_vm_deallocate(task(), src.addr, SIZE);
        if kr != 0 {
            return Err(format!("mach_vm_map failed ({kr:#x})"));
        }
        Ok(Host { addr, owned: true })
    }
}

/// Memory that was mapped and is not any more.
fn unmapped() -> Result<Host, String> {
    let h = allocate(VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE)?;
    // SAFETY: freeing our own allocation.
    unsafe { mach_vm_deallocate(task(), h.addr, SIZE) };
    Ok(Host { addr: h.addr, owned: false })
}

/// Ask the framework (or the stand-in) case by case; one line each.
pub fn map_rules() -> Result<String, String> {
    let rw = VM_PROT_READ | VM_PROT_WRITE;
    let rwx = rw | VM_PROT_EXECUTE;
    let (r, x, w) = (HV_MEMORY_READ, HV_MEMORY_EXEC, HV_MEMORY_WRITE);
    type Make = Box<dyn Fn() -> Result<Host, String>>;
    let cases: Vec<(&str, Make, u64)> = vec![
        ("RW, at most RWX, as RWX", Box::new(move || allocate(rw, rwx)), r | w | x),
        ("RW, at most RWX, as R", Box::new(move || allocate(rw, rwx)), r),
        ("R, at most RWX, as RX", Box::new(move || allocate(VM_PROT_READ, rwx)), r | x),
        ("R, at most RW, as RX", Box::new(move || allocate(VM_PROT_READ, rw)), r | x),
        ("RW, at most RW, as RWX", Box::new(move || allocate(rw, rw)), r | w | x),
        ("R, at most R, as RX", Box::new(|| allocate(VM_PROT_READ, VM_PROT_READ)), r | x),
        ("R, at most R, as R", Box::new(|| allocate(VM_PROT_READ, VM_PROT_READ)), r),
        (
            "RX, at most RX, as RX",
            Box::new(move || {
                allocate(VM_PROT_READ | VM_PROT_EXECUTE, VM_PROT_READ | VM_PROT_EXECUTE)
            }),
            r | x,
        ),
        ("shared entry of read-only memory, as RX", Box::new(shared_read_only), r | x),
        ("unmapped, as R", Box::new(unmapped), r),
    ];
    // SAFETY: a VM for this process, with no vCPU, destroyed below.
    unsafe {
        let cfg = hv_vm_config_create();
        check(hv_vm_config_set_ipa_size(cfg, 36), "hv_vm_config_set_ipa_size")?;
        check(hv_vm_create(cfg), "hv_vm_create")?;
    }
    let mut out = String::new();
    for (i, (name, make, flags)) in cases.iter().enumerate() {
        let host = match make() {
            Ok(h) => h,
            Err(e) => {
                out.push_str(&format!("{name}: not set up ({e})\n"));
                continue;
            }
        };
        let ipa = 0x1000_0000 + i as u64 * 0x10_0000;
        // SAFETY: mapping host memory of ours into the VM, and taking it
        // out again before the memory goes.
        let rc = unsafe { hv_vm_map(host.addr as *mut _, ipa, SIZE as usize, *flags) };
        if rc == 0 {
            // SAFETY: as above.
            unsafe { hv_vm_unmap(ipa, SIZE as usize) };
            out.push_str(&format!("{name}: mapped\n"));
        } else {
            out.push_str(&format!("{name}: refused\n"));
        }
        if host.owned {
            // SAFETY: freeing our own memory, no longer in the VM.
            unsafe { mach_vm_deallocate(task(), host.addr, SIZE) };
        }
    }
    // SAFETY: destroying the VM made above; it has no vCPU.
    let rc = unsafe { hv_vm_destroy() };
    check(rc, "hv_vm_destroy")?;
    Ok(out.trim_end().to_string())
}
