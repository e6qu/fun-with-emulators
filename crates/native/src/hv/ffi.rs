//! Hypervisor.framework (arm64): the calls and constants the backend uses,
//! each made to the framework or, under `--hv-standin`, to the stand-in.

#![allow(non_camel_case_types)]

use std::os::raw::c_void;

pub type hv_return_t = i32;
pub type hv_vcpu_t = u64;
pub type hv_reg_t = u32;
pub type hv_sys_reg_t = u16;
pub type hv_vm_config_t = *mut c_void;

#[repr(C)]
pub struct hv_vcpu_exit_exception_t {
    pub syndrome: u64,
    pub virtual_address: u64,
    pub physical_address: u64,
}

#[repr(C)]
pub struct hv_vcpu_exit_t {
    pub reason: u32,
    pub exception: hv_vcpu_exit_exception_t,
}

pub const HV_EXIT_REASON_CANCELED: u32 = 0;
pub const HV_EXIT_REASON_EXCEPTION: u32 = 1;
pub const HV_EXIT_REASON_VTIMER_ACTIVATED: u32 = 2;

pub const HV_REG_X0: hv_reg_t = 0;
pub const HV_REG_PC: hv_reg_t = 31;
pub const HV_REG_FPCR: hv_reg_t = 32;
pub const HV_REG_FPSR: hv_reg_t = 33;
pub const HV_REG_CPSR: hv_reg_t = 34;

pub const HV_SYS_REG_SCTLR_EL1: hv_sys_reg_t = 0xc080;
pub const HV_SYS_REG_CPACR_EL1: hv_sys_reg_t = 0xc082;
pub const HV_SYS_REG_TTBR0_EL1: hv_sys_reg_t = 0xc100;
pub const HV_SYS_REG_TCR_EL1: hv_sys_reg_t = 0xc102;
pub const HV_SYS_REG_SPSR_EL1: hv_sys_reg_t = 0xc200;
pub const HV_SYS_REG_ELR_EL1: hv_sys_reg_t = 0xc201;
pub const HV_SYS_REG_SP_EL0: hv_sys_reg_t = 0xc208;
pub const HV_SYS_REG_ESR_EL1: hv_sys_reg_t = 0xc290;
pub const HV_SYS_REG_FAR_EL1: hv_sys_reg_t = 0xc300;
pub const HV_SYS_REG_MAIR_EL1: hv_sys_reg_t = 0xc510;
pub const HV_SYS_REG_VBAR_EL1: hv_sys_reg_t = 0xc600;
pub const HV_SYS_REG_CNTKCTL_EL1: hv_sys_reg_t = 0xc708;
pub const HV_SYS_REG_TPIDR_EL0: hv_sys_reg_t = 0xde82;

pub const HV_MEMORY_READ: u64 = 1;
pub const HV_MEMORY_WRITE: u64 = 2;
pub const HV_MEMORY_EXEC: u64 = 4;

/// The framework itself.
mod framework {
    use super::*;

    #[link(name = "Hypervisor", kind = "framework")]
    unsafe extern "C" {
        pub fn hv_vm_config_create() -> hv_vm_config_t;
        pub fn hv_vm_config_set_ipa_size(
            config: hv_vm_config_t,
            ipa_bit_length: u32,
        ) -> hv_return_t;
        pub fn hv_vm_create(config: hv_vm_config_t) -> hv_return_t;
        pub fn hv_vm_destroy() -> hv_return_t;
        pub fn hv_vm_map(addr: *mut c_void, ipa: u64, size: usize, flags: u64) -> hv_return_t;
        pub fn hv_vm_unmap(ipa: u64, size: usize) -> hv_return_t;
        pub fn hv_vcpu_create(
            vcpu: *mut hv_vcpu_t,
            exit: *mut *mut hv_vcpu_exit_t,
            config: *mut c_void,
        ) -> hv_return_t;
        pub fn hv_vcpu_run(vcpu: hv_vcpu_t) -> hv_return_t;
        pub fn hv_vcpu_destroy(vcpu: hv_vcpu_t) -> hv_return_t;
        pub fn hv_vcpu_get_vtimer_offset(vcpu: hv_vcpu_t, offset: *mut u64) -> hv_return_t;
        pub fn hv_vcpu_set_vtimer_offset(vcpu: hv_vcpu_t, offset: u64) -> hv_return_t;
        pub fn hv_vcpus_exit(vcpus: *mut hv_vcpu_t, count: u32) -> hv_return_t;
        pub fn hv_vcpu_get_reg(vcpu: hv_vcpu_t, reg: hv_reg_t, value: *mut u64) -> hv_return_t;
        pub fn hv_vcpu_set_reg(vcpu: hv_vcpu_t, reg: hv_reg_t, value: u64) -> hv_return_t;
        pub fn hv_vcpu_get_sys_reg(
            vcpu: hv_vcpu_t,
            reg: hv_sys_reg_t,
            value: *mut u64,
        ) -> hv_return_t;
        pub fn hv_vcpu_set_sys_reg(vcpu: hv_vcpu_t, reg: hv_sys_reg_t, value: u64) -> hv_return_t;
        pub fn hv_vcpu_get_simd_fp_reg(vcpu: hv_vcpu_t, reg: u32, value: *mut u128) -> hv_return_t;
        // Takes the value by value in `q0`, which Rust cannot pass; called
        // only through [`set_simd_fp_reg`], so its real signature does not
        // matter.
        fn hv_vcpu_set_simd_fp_reg();
    }

    /// `hv_vcpu_set_simd_fp_reg(vcpu, reg, *value)`: load the 16 bytes into
    /// `q0`, where the framework expects them, and tail-call it.
    ///
    /// # Safety
    /// `value` must point to 16 readable bytes; `vcpu` must be the calling
    /// thread's vCPU.
    #[unsafe(naked)]
    pub unsafe extern "C" fn set_simd_fp_reg(
        vcpu: hv_vcpu_t,
        reg: u32,
        value: *const u128,
    ) -> hv_return_t {
        core::arch::naked_asm!("ldr q0, [x2]", "b {f}", f = sym hv_vcpu_set_simd_fp_reg)
    }
}

/// Each call goes to the framework, or to the stand-in under
/// `--hv-standin` (see [`super::standin`]).
macro_rules! calls {
    ($(fn $name:ident($($arg:ident: $ty:ty),*) -> hv_return_t => $standin:ident;)*) => {$(
        /// # Safety
        /// As for the framework call of this name.
        pub unsafe fn $name($($arg: $ty),*) -> hv_return_t {
            if super::standin::active() {
                super::standin::$standin($($arg),*)
            } else {
                // SAFETY: the caller keeps the framework's contract.
                unsafe { framework::$name($($arg),*) }
            }
        }
    )*};
}

calls! {
    fn hv_vm_config_set_ipa_size(config: hv_vm_config_t, bits: u32) -> hv_return_t
        => vm_config_set_ipa_size;
    fn hv_vm_create(config: hv_vm_config_t) -> hv_return_t => vm_create;
    fn hv_vm_destroy() -> hv_return_t => vm_destroy;
    fn hv_vm_map(addr: *mut c_void, ipa: u64, size: usize, flags: u64) -> hv_return_t => vm_map;
    fn hv_vm_unmap(ipa: u64, size: usize) -> hv_return_t => vm_unmap;
    fn hv_vcpu_create(vcpu: *mut hv_vcpu_t, exit: *mut *mut hv_vcpu_exit_t, config: *mut c_void)
        -> hv_return_t => vcpu_create;
    fn hv_vcpu_run(vcpu: hv_vcpu_t) -> hv_return_t => vcpu_run;
    fn hv_vcpu_destroy(vcpu: hv_vcpu_t) -> hv_return_t => vcpu_destroy;
    fn hv_vcpu_get_vtimer_offset(vcpu: hv_vcpu_t, offset: *mut u64) -> hv_return_t
        => vcpu_get_vtimer_offset;
    fn hv_vcpu_set_vtimer_offset(vcpu: hv_vcpu_t, offset: u64) -> hv_return_t
        => vcpu_set_vtimer_offset;
    fn hv_vcpus_exit(vcpus: *mut hv_vcpu_t, count: u32) -> hv_return_t => vcpus_exit;
    fn hv_vcpu_get_reg(vcpu: hv_vcpu_t, reg: hv_reg_t, value: *mut u64) -> hv_return_t
        => vcpu_get_reg;
    fn hv_vcpu_set_reg(vcpu: hv_vcpu_t, reg: hv_reg_t, value: u64) -> hv_return_t
        => vcpu_set_reg;
    fn hv_vcpu_get_sys_reg(vcpu: hv_vcpu_t, reg: hv_sys_reg_t, value: *mut u64) -> hv_return_t
        => vcpu_get_sys_reg;
    fn hv_vcpu_set_sys_reg(vcpu: hv_vcpu_t, reg: hv_sys_reg_t, value: u64) -> hv_return_t
        => vcpu_set_sys_reg;
    fn hv_vcpu_get_simd_fp_reg(vcpu: hv_vcpu_t, reg: u32, value: *mut u128) -> hv_return_t
        => vcpu_get_simd_fp_reg;
    fn set_simd_fp_reg(vcpu: hv_vcpu_t, reg: u32, value: *const u128) -> hv_return_t
        => vcpu_set_simd_fp_reg;
}

/// # Safety
/// As for the framework call.
pub unsafe fn hv_vm_config_create() -> hv_vm_config_t {
    if super::standin::active() {
        super::standin::vm_config_create()
    } else {
        // SAFETY: no arguments.
        unsafe { framework::hv_vm_config_create() }
    }
}

unsafe extern "C" {
    /// The host's counter ticks (libSystem), which the guest's virtual
    /// counter follows less the vCPU's timer offset.
    pub fn mach_absolute_time() -> u64;
}

/// `Ok` for `HV_SUCCESS`, else an error naming the call.
pub fn check(rc: hv_return_t, what: &str) -> Result<(), String> {
    if rc == 0 { Ok(()) } else { Err(format!("{what} failed: {rc:#010x}")) }
}
