//! `fwe --hv-spike`: the smallest possible VM, as a check that the
//! hypervisor works on a machine. It maps RAM at a low guest-physical
//! address, runs a tiny guest there at EL1 with the MMU off, services its two
//! "system calls" (made with `hvc #0`) and reports what it printed and the
//! status it exited with. The real backend is in the rest of this module;
//! see `docs/hypervisor.md`.

/// What the spike guest produced: what it wrote to fd 1 and the status it
/// exited with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spike {
    pub stdout: Vec<u8>,
    pub exit_code: i32,
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use imp::spike;

/// On any other host the hypervisor backend does not exist.
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
pub fn spike() -> Result<Spike, String> {
    Err("the hypervisor backend requires macOS on Apple Silicon".into())
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod imp {
    use super::Spike;
    use std::os::raw::c_void;

    // Hypervisor.framework, arm64. Only the handful of calls the spike needs.
    #[allow(non_camel_case_types)]
    type hv_return_t = i32;
    #[allow(non_camel_case_types)]
    type hv_vcpu_t = u64;
    #[allow(non_camel_case_types)]
    type hv_reg_t = u32;

    #[repr(C)]
    struct hv_vcpu_exit_exception_t {
        syndrome: u64,
        virtual_address: u64,
        physical_address: u64,
    }
    #[repr(C)]
    struct hv_vcpu_exit_t {
        reason: u32,
        exception: hv_vcpu_exit_exception_t,
    }

    const HV_EXIT_REASON_EXCEPTION: u32 = 1;

    // hv_reg_t: X0..X30 = 0..30, then PC = 31, FPCR, FPSR, CPSR = 34.
    const HV_REG_X0: hv_reg_t = 0;
    const HV_REG_PC: hv_reg_t = 31;
    const HV_REG_CPSR: hv_reg_t = 34;

    const HV_MEMORY_READ: u64 = 1;
    const HV_MEMORY_WRITE: u64 = 2;
    const HV_MEMORY_EXEC: u64 = 4;

    // ESR exception class for an `HVC` taken from AArch64.
    const EC_HVC: u64 = 0x16;
    // PSTATE for EL1h with DAIF masked.
    const PSTATE_EL1H: u64 = 0x3c5;
    // The `HVC #0` instruction, used to tell whether PC still sits on it.
    const HVC_0: u32 = 0xd400_0002;

    // SAFETY: these are the Hypervisor.framework entry points; each call below
    // documents the arguments it passes.
    #[link(name = "Hypervisor", kind = "framework")]
    unsafe extern "C" {
        fn hv_vm_create(config: *mut c_void) -> hv_return_t;
        fn hv_vm_destroy() -> hv_return_t;
        fn hv_vm_map(addr: *mut c_void, ipa: u64, size: usize, flags: u64) -> hv_return_t;
        fn hv_vcpu_create(
            vcpu: *mut hv_vcpu_t,
            exit: *mut *mut hv_vcpu_exit_t,
            config: *mut c_void,
        ) -> hv_return_t;
        fn hv_vcpu_destroy(vcpu: hv_vcpu_t) -> hv_return_t;
        fn hv_vcpu_run(vcpu: hv_vcpu_t) -> hv_return_t;
        fn hv_vcpu_set_reg(vcpu: hv_vcpu_t, reg: hv_reg_t, value: u64) -> hv_return_t;
        fn hv_vcpu_get_reg(vcpu: hv_vcpu_t, reg: hv_reg_t, value: *mut u64) -> hv_return_t;
    }

    /// Guest-physical base the RAM is mapped at: deliberately low, in the
    /// region macOS's `__PAGEZERO` would deny to the native backend.
    const BASE: u64 = 0x0040_0000;
    const RAM_SIZE: usize = 0x20_0000; // 2 MiB
    const MSG_OFF: usize = 0x100;
    const MSG: &[u8] = b"hv: hello from the guest\n";

    /// The guest program (assembled from `guest.S`). Its "syscall" ABI matches
    /// Linux arm64 — `x8` number, `x0..` arguments — but it uses `HVC #0` to
    /// trap to the VMM. It does `write(1, MSG, 25)` then `exit_group(42)`.
    const GUEST: [u32; 10] = [
        0xd280_0020, // mov x0, #1
        0xd2a0_0801, // movz x1, #0x40, lsl #16
        0xf280_2001, // movk x1, #0x100
        0xd280_0322, // mov x2, #25
        0xd280_0808, // mov x8, #64   (write)
        0xd400_0002, // hvc #0
        0xd280_0540, // mov x0, #42
        0xd280_0bc8, // mov x8, #94   (exit_group)
        0xd400_0002, // hvc #0
        0x1400_0000, // b .
    ];

    fn check(rc: hv_return_t, what: &str) -> Result<(), String> {
        if rc == 0 { Ok(()) } else { Err(format!("{what} failed: {rc:#010x}")) }
    }

    /// Run the spike guest in a fresh VM and return what it produced.
    pub fn spike() -> Result<Spike, String> {
        // SAFETY: a fresh anonymous RW mapping to back guest RAM.
        let ram = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                RAM_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if ram == libc::MAP_FAILED {
            return Err("allocating guest RAM failed".into());
        }
        // SAFETY: `ram` is the writable RAM_SIZE mapping just made.
        let result = unsafe { run(ram) };
        // SAFETY: releasing the mapping we just made, whatever happened.
        unsafe { libc::munmap(ram, RAM_SIZE) };
        result
    }

    /// # Safety
    /// `ram` must point to a writable mapping of `RAM_SIZE` bytes.
    unsafe fn run(ram: *mut c_void) -> Result<Spike, String> {
        // Lay out guest memory: code at offset 0, message at MSG_OFF.
        // SAFETY: both regions lie within the RAM_SIZE mapping.
        unsafe {
            let code = ram as *mut u32;
            for (i, w) in GUEST.iter().enumerate() {
                code.add(i).write(*w);
            }
            std::ptr::copy_nonoverlapping(MSG.as_ptr(), (ram as *mut u8).add(MSG_OFF), MSG.len());
        }

        // Creating the VM is also the capability probe: without the
        // entitlement, or on a host without hypervisor support, it fails here
        // and the caller reports it rather than crashing.
        // SAFETY: a VM for this process; config defaulted.
        check(unsafe { hv_vm_create(std::ptr::null_mut()) }, "hv_vm_create")?;

        let run = || -> Result<Spike, String> {
            let flags = HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC;
            // SAFETY: mapping our RAM into the guest's physical space, RWX.
            let rc = unsafe { hv_vm_map(ram, BASE, RAM_SIZE, flags) };
            check(rc, "hv_vm_map")?;

            let mut vcpu: hv_vcpu_t = 0;
            let mut exit: *mut hv_vcpu_exit_t = std::ptr::null_mut();
            // SAFETY: out-params for the new vCPU and its exit record.
            let rc = unsafe { hv_vcpu_create(&mut vcpu, &mut exit, std::ptr::null_mut()) };
            check(rc, "hv_vcpu_create")?;

            // SAFETY: `vcpu`/`exit` are from the successful create above, and
            // `ram` is the mapping handed to `hv_vm_map`.
            let outcome = unsafe { drive(vcpu, exit, ram) };
            // SAFETY: the vCPU was created above.
            unsafe { hv_vcpu_destroy(vcpu) };
            outcome
        };

        let outcome = run();
        // SAFETY: destroying the VM created above, regardless of outcome.
        unsafe { hv_vm_destroy() };
        outcome
    }

    /// # Safety
    /// `vcpu`/`exit` must come from a successful `hv_vcpu_create`, and `ram`
    /// must be the mapping handed to `hv_vm_map`.
    unsafe fn drive(
        vcpu: hv_vcpu_t,
        exit: *mut hv_vcpu_exit_t,
        ram: *mut c_void,
    ) -> Result<Spike, String> {
        let get = |reg: hv_reg_t| -> Result<u64, String> {
            let mut v = 0u64;
            // SAFETY: reading a register of our vCPU into a local.
            check(unsafe { hv_vcpu_get_reg(vcpu, reg, &mut v) }, "hv_vcpu_get_reg")?;
            Ok(v)
        };
        let set = |reg: hv_reg_t, v: u64| -> Result<(), String> {
            // SAFETY: writing a register of our vCPU.
            check(unsafe { hv_vcpu_set_reg(vcpu, reg, v) }, "hv_vcpu_set_reg")
        };

        set(HV_REG_CPSR, PSTATE_EL1H)?;
        set(HV_REG_PC, BASE)?;

        let mut stdout = Vec::new();
        loop {
            // SAFETY: running our vCPU; `exit` is refreshed in place by HVF.
            check(unsafe { hv_vcpu_run(vcpu) }, "hv_vcpu_run")?;
            // SAFETY: `exit` points to HVF's per-vCPU exit record.
            let e = unsafe { &*exit };
            if e.reason != HV_EXIT_REASON_EXCEPTION {
                return Err(format!("unexpected vCPU exit reason {}", e.reason));
            }
            let ec = (e.exception.syndrome >> 26) & 0x3f;
            if ec != EC_HVC {
                let pc = get(HV_REG_PC)?;
                return Err(format!(
                    "unexpected exception: EC {ec:#x}, syndrome {:#x}, pc {pc:#x}",
                    e.exception.syndrome
                ));
            }

            let nr = get(HV_REG_X0 + 8)?;
            let (a0, a1, a2) = (get(HV_REG_X0)?, get(HV_REG_X0 + 1)?, get(HV_REG_X0 + 2)?);
            match nr {
                64 => {
                    // write(fd, buf, len). The MMU is off, so `buf` is a
                    // guest-physical address inside our RAM.
                    let ret = if a1 >= BASE && a1.saturating_add(a2) <= BASE + RAM_SIZE as u64 {
                        let off = (a1 - BASE) as usize;
                        // SAFETY: the range lies within the RAM mapping.
                        let bytes = unsafe {
                            std::slice::from_raw_parts((ram as *const u8).add(off), a2 as usize)
                        };
                        if a0 == 1 || a0 == 2 {
                            stdout.extend_from_slice(bytes);
                        }
                        a2
                    } else {
                        (-14i64) as u64 // -EFAULT
                    };
                    set(HV_REG_X0, ret)?;
                }
                93 | 94 => {
                    return Ok(Spike { stdout, exit_code: a0 as i32 });
                }
                _ => set(HV_REG_X0, (-38i64) as u64)?, // -ENOSYS
            }

            // Step past the HVC if HVF left PC sitting on it.
            let pc = get(HV_REG_PC)?;
            if pc >= BASE && pc < BASE + RAM_SIZE as u64 {
                // SAFETY: reading the instruction word at PC within our RAM.
                let insn =
                    unsafe { ((ram as *const u8).add((pc - BASE) as usize) as *const u32).read() };
                if insn == HVC_0 {
                    set(HV_REG_PC, pc + 4)?;
                }
            }
        }
    }
}
