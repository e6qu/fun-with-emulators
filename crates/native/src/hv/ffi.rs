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
pub const HV_SYS_REG_ID_AA64PFR1_EL1: hv_sys_reg_t = 0xc021;
pub const HV_SYS_REG_ID_AA64ISAR1_EL1: hv_sys_reg_t = 0xc031;
/// The pointer-authentication keys: APIA, APIB, APDA, APDB, APGA, each a
/// low and a high half.
pub const HV_SYS_REG_PAC_KEYS: [hv_sys_reg_t; 10] =
    [0xc108, 0xc109, 0xc10a, 0xc10b, 0xc110, 0xc111, 0xc112, 0xc113, 0xc118, 0xc119];

pub const HV_MEMORY_READ: u64 = 1;
pub const HV_MEMORY_WRITE: u64 = 2;
pub const HV_MEMORY_EXEC: u64 = 4;

/// The framework itself, loaded on first use: linking it would cost every
/// process its loading at startup, and most never run a VM.
pub(super) mod framework {
    use super::*;
    use std::sync::OnceLock;

    /// `HV_ERROR`: what a call returns when the framework cannot be loaded.
    const HV_ERROR: hv_return_t = 0xfae9_4001_u32 as i32;

    macro_rules! table {
        ($(fn $name:ident($($arg:ident: $ty:ty),*) -> $ret:ty = $fail:expr;)*) => {
            /// The framework's entry points, all resolved at once (a call
            /// made in a signal handler then never resolves one).
            #[allow(non_snake_case)]
            struct Table {
                $($name: Option<unsafe extern "C" fn($($ty),*) -> $ret>,)*
                hv_vcpu_set_simd_fp_reg: Option<unsafe extern "C" fn()>,
            }

            fn load() -> Table {
                // SAFETY: loading a system framework by its absolute path.
                let h = unsafe {
                    libc::dlopen(
                        c"/System/Library/Frameworks/Hypervisor.framework/Hypervisor".as_ptr(),
                        libc::RTLD_NOW | libc::RTLD_LOCAL,
                    )
                };
                let sym = |name: &std::ffi::CStr| -> *mut c_void {
                    if h.is_null() {
                        return std::ptr::null_mut();
                    }
                    // SAFETY: looking up a symbol in the handle just opened.
                    unsafe { libc::dlsym(h, name.as_ptr()) }
                };
                Table {
                    $(
                        // SAFETY: the symbol of this name has this signature
                        // (Hypervisor.framework's headers); null is None.
                        $name: unsafe {
                            std::mem::transmute::<*mut c_void, Option<unsafe extern "C" fn($($ty),*) -> $ret>>(
                                sym(&std::ffi::CString::new(stringify!($name)).unwrap()),
                            )
                        },
                    )*
                    // SAFETY: as above; called only through `set_simd_fp_reg`.
                    hv_vcpu_set_simd_fp_reg: unsafe {
                        std::mem::transmute::<*mut c_void, Option<unsafe extern "C" fn()>>(
                            sym(c"hv_vcpu_set_simd_fp_reg"),
                        )
                    },
                }
            }

            $(
                /// # Safety
                /// As for the framework call of this name.
                pub unsafe fn $name($($arg: $ty),*) -> $ret {
                    match table().$name {
                        // SAFETY: the caller keeps the framework's contract.
                        Some(f) => unsafe { f($($arg),*) },
                        None => $fail,
                    }
                }
            )*
        };
    }

    fn table() -> &'static Table {
        static TABLE: OnceLock<Table> = OnceLock::new();
        TABLE.get_or_init(load)
    }

    table! {
        fn hv_vm_config_create() -> hv_vm_config_t = std::ptr::null_mut();
        fn hv_vm_config_set_ipa_size(config: hv_vm_config_t, ipa_bit_length: u32) -> hv_return_t
            = HV_ERROR;
        fn hv_vm_config_get_max_ipa_size(ipa_bit_length: *mut u32) -> hv_return_t = HV_ERROR;
        fn hv_vm_create(config: hv_vm_config_t) -> hv_return_t = HV_ERROR;
        fn hv_vm_destroy() -> hv_return_t = HV_ERROR;
        fn hv_vm_map(addr: *mut c_void, ipa: u64, size: usize, flags: u64) -> hv_return_t
            = HV_ERROR;
        fn hv_vm_unmap(ipa: u64, size: usize) -> hv_return_t = HV_ERROR;
        fn hv_vcpu_create(
            vcpu: *mut hv_vcpu_t,
            exit: *mut *mut hv_vcpu_exit_t,
            config: *mut c_void
        ) -> hv_return_t = HV_ERROR;
        fn hv_vcpu_run(vcpu: hv_vcpu_t) -> hv_return_t = HV_ERROR;
        fn hv_vcpu_destroy(vcpu: hv_vcpu_t) -> hv_return_t = HV_ERROR;
        fn hv_vcpu_get_vtimer_offset(vcpu: hv_vcpu_t, offset: *mut u64) -> hv_return_t
            = HV_ERROR;
        fn hv_vcpu_set_vtimer_offset(vcpu: hv_vcpu_t, offset: u64) -> hv_return_t = HV_ERROR;
        fn hv_vcpus_exit(vcpus: *mut hv_vcpu_t, count: u32) -> hv_return_t = HV_ERROR;
        fn hv_vcpu_get_reg(vcpu: hv_vcpu_t, reg: hv_reg_t, value: *mut u64) -> hv_return_t
            = HV_ERROR;
        fn hv_vcpu_set_reg(vcpu: hv_vcpu_t, reg: hv_reg_t, value: u64) -> hv_return_t
            = HV_ERROR;
        fn hv_vcpu_get_sys_reg(vcpu: hv_vcpu_t, reg: hv_sys_reg_t, value: *mut u64)
            -> hv_return_t = HV_ERROR;
        fn hv_vcpu_set_sys_reg(vcpu: hv_vcpu_t, reg: hv_sys_reg_t, value: u64) -> hv_return_t
            = HV_ERROR;
        fn hv_vcpu_get_simd_fp_reg(vcpu: hv_vcpu_t, reg: u32, value: *mut u128) -> hv_return_t
            = HV_ERROR;
    }

    /// `hv_vcpu_set_simd_fp_reg(vcpu, reg, *value)`, which takes the value
    /// by value in `q0`, which Rust cannot pass.
    ///
    /// # Safety
    /// `value` must point to 16 readable bytes; `vcpu` must be the calling
    /// thread's vCPU.
    pub unsafe fn set_simd_fp_reg(vcpu: hv_vcpu_t, reg: u32, value: *const u128) -> hv_return_t {
        let Some(f) = table().hv_vcpu_set_simd_fp_reg else { return HV_ERROR };
        // SAFETY: the caller's guarantees; `f` is the framework's entry.
        unsafe { with_q0(vcpu, reg, value, f) }
    }

    /// Load the 16 bytes at `value` into `q0`, where the framework expects
    /// them, and tail-call `f`.
    #[unsafe(naked)]
    unsafe extern "C" fn with_q0(
        vcpu: hv_vcpu_t,
        reg: u32,
        value: *const u128,
        f: unsafe extern "C" fn(),
    ) -> hv_return_t {
        core::arch::naked_asm!("ldr q0, [x2]", "br x3")
    }
}

/// Each call goes to the framework, or to the stand-in under
/// `--hv-standin` (see [`super::standin`]). Calls that change the VM's state
/// are recorded by the flight recorder (`rec`, see [`super::record`]; a
/// vCPU's destruction without waiting for the disk, `unsynced`), runs are
/// counted (`run`); register accesses and stops are not (`quiet`): a fork's
/// pause and every guest signal stop vCPUs, often.
macro_rules! calls {
    ($(fn $name:ident($($arg:ident: $ty:ty),*) -> hv_return_t => $standin:ident, $kind:ident;)*) => {$(
        /// # Safety
        /// As for the framework call of this name.
        pub unsafe fn $name($($arg: $ty),*) -> hv_return_t {
            calls!(@before $kind $name $($arg)*);
            let rc = if super::standin::active() {
                super::standin::$standin($($arg),*)
            } else {
                // SAFETY: the caller keeps the framework's contract.
                unsafe { framework::$name($($arg),*) }
            };
            calls!(@after $kind $name rc);
            rc
        }
    )*};
    (@before rec $name:ident $($arg:ident)*) => {
        super::record::begin(stringify!($name), &[$($arg as u64),*], true)
    };
    (@before unsynced $name:ident $($arg:ident)*) => {
        super::record::begin(stringify!($name), &[$($arg as u64),*], false)
    };
    (@before run $name:ident $($arg:ident)*) => { super::record::count_run() };
    (@before quiet $name:ident $($arg:ident)*) => {};
    (@after rec $name:ident $rc:ident) => { super::record::end(stringify!($name), $rc, true) };
    (@after unsynced $name:ident $rc:ident) => {
        super::record::end(stringify!($name), $rc, false)
    };
    (@after $kind:ident $name:ident $rc:ident) => {};
}

calls! {
    fn hv_vm_config_set_ipa_size(config: hv_vm_config_t, bits: u32) -> hv_return_t
        => vm_config_set_ipa_size, quiet;
    fn hv_vm_config_get_max_ipa_size(bits: *mut u32) -> hv_return_t
        => vm_config_get_max_ipa_size, quiet;
    fn hv_vm_create(config: hv_vm_config_t) -> hv_return_t => vm_create, rec;
    fn hv_vm_destroy() -> hv_return_t => vm_destroy, rec;
    fn hv_vm_map(addr: *mut c_void, ipa: u64, size: usize, flags: u64) -> hv_return_t => vm_map, rec;
    fn hv_vm_unmap(ipa: u64, size: usize) -> hv_return_t => vm_unmap, rec;
    fn hv_vcpu_create(vcpu: *mut hv_vcpu_t, exit: *mut *mut hv_vcpu_exit_t, config: *mut c_void)
        -> hv_return_t => vcpu_create, rec;
    fn hv_vcpu_run(vcpu: hv_vcpu_t) -> hv_return_t => vcpu_run, run;
    fn hv_vcpu_destroy(vcpu: hv_vcpu_t) -> hv_return_t => vcpu_destroy, unsynced;
    fn hv_vcpu_get_vtimer_offset(vcpu: hv_vcpu_t, offset: *mut u64) -> hv_return_t
        => vcpu_get_vtimer_offset, quiet;
    fn hv_vcpu_set_vtimer_offset(vcpu: hv_vcpu_t, offset: u64) -> hv_return_t
        => vcpu_set_vtimer_offset, quiet;
    fn hv_vcpus_exit(vcpus: *mut hv_vcpu_t, count: u32) -> hv_return_t => vcpus_exit, quiet;
    fn hv_vcpu_get_reg(vcpu: hv_vcpu_t, reg: hv_reg_t, value: *mut u64) -> hv_return_t
        => vcpu_get_reg, quiet;
    fn hv_vcpu_set_reg(vcpu: hv_vcpu_t, reg: hv_reg_t, value: u64) -> hv_return_t
        => vcpu_set_reg, quiet;
    fn hv_vcpu_get_sys_reg(vcpu: hv_vcpu_t, reg: hv_sys_reg_t, value: *mut u64) -> hv_return_t
        => vcpu_get_sys_reg, quiet;
    fn hv_vcpu_set_sys_reg(vcpu: hv_vcpu_t, reg: hv_sys_reg_t, value: u64) -> hv_return_t
        => vcpu_set_sys_reg, quiet;
    fn hv_vcpu_get_simd_fp_reg(vcpu: hv_vcpu_t, reg: u32, value: *mut u128) -> hv_return_t
        => vcpu_get_simd_fp_reg, quiet;
    fn set_simd_fp_reg(vcpu: hv_vcpu_t, reg: u32, value: *const u128) -> hv_return_t
        => vcpu_set_simd_fp_reg, quiet;
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
