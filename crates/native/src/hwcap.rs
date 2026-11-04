//! CPU features reported to the guest through `AT_HWCAP` and `AT_HWCAP2`.
//!
//! Only features the guest can use directly are reported. `CPUID` (trapping
//! reads of ID registers), SVE and SME (which need kernel-managed state) and
//! pointer authentication (whose keys the host controls) are left out.

use fwe_abi::hwcap as h1;
#[cfg(target_os = "macos")]
use fwe_abi::hwcap2 as h2;

/// (macOS `hw.optional.*` sysctl, `AT_HWCAP` bits, `AT_HWCAP2` bits)
#[cfg(target_os = "macos")]
const FEATURES: &[(&str, u64, u64)] = &[
    ("hw.optional.arm.FEAT_AES", h1::AES, 0),
    ("hw.optional.arm.FEAT_PMULL", h1::PMULL, 0),
    ("hw.optional.arm.FEAT_SHA1", h1::SHA1, 0),
    ("hw.optional.arm.FEAT_SHA256", h1::SHA2, 0),
    ("hw.optional.armv8_crc32", h1::CRC32, 0),
    ("hw.optional.arm.FEAT_LSE", h1::ATOMICS, 0),
    ("hw.optional.arm.FEAT_FP16", h1::FPHP | h1::ASIMDHP, 0),
    ("hw.optional.arm.FEAT_RDM", h1::ASIMDRDM, 0),
    ("hw.optional.arm.FEAT_JSCVT", h1::JSCVT, 0),
    ("hw.optional.arm.FEAT_FCMA", h1::FCMA, 0),
    ("hw.optional.arm.FEAT_LRCPC", h1::LRCPC, 0),
    ("hw.optional.arm.FEAT_DPB", h1::DCPOP, 0),
    ("hw.optional.arm.FEAT_SHA3", h1::SHA3, 0),
    ("hw.optional.arm.FEAT_DotProd", h1::ASIMDDP, 0),
    ("hw.optional.arm.FEAT_SHA512", h1::SHA512, 0),
    ("hw.optional.arm.FEAT_FHM", h1::ASIMDFHM, 0),
    ("hw.optional.arm.FEAT_DIT", h1::DIT, 0),
    ("hw.optional.arm.FEAT_LSE2", h1::USCAT, 0),
    ("hw.optional.arm.FEAT_LRCPC2", h1::ILRCPC, 0),
    ("hw.optional.arm.FEAT_FlagM", h1::FLAGM, 0),
    ("hw.optional.arm.FEAT_SSBS", h1::SSBS, 0),
    ("hw.optional.arm.FEAT_SB", h1::SB, 0),
    ("hw.optional.arm.FEAT_DPB2", 0, h2::DCPODP),
    ("hw.optional.arm.FEAT_FlagM2", 0, h2::FLAGM2),
    ("hw.optional.arm.FEAT_FRINTTS", 0, h2::FRINT),
    ("hw.optional.arm.FEAT_I8MM", 0, h2::I8MM),
    ("hw.optional.arm.FEAT_BF16", 0, h2::BF16),
    ("hw.optional.arm.FEAT_BTI", 0, h2::BTI),
    ("hw.optional.arm.FEAT_ECV", 0, h2::ECV),
    ("hw.optional.arm.FEAT_AFP", 0, h2::AFP),
    ("hw.optional.arm.FEAT_RPRES", 0, h2::RPRES),
    ("hw.optional.arm.FEAT_WFxT", 0, h2::WFXT),
    ("hw.optional.arm.FEAT_EBF16", 0, h2::EBF16),
    ("hw.optional.arm.FEAT_CSSC", 0, h2::CSSC),
    ("hw.optional.arm.FEAT_HBC", 0, h2::HBC),
];

#[cfg(target_os = "macos")]
fn sysctl_flag(name: &str) -> bool {
    let name = std::ffi::CString::new(name).unwrap();
    let mut value: i32 = 0;
    let mut len = std::mem::size_of::<i32>();
    // SAFETY: `value` and `len` are valid out-parameters of matching size.
    let r = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            (&mut value as *mut i32).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    r == 0 && value != 0
}

/// `(AT_HWCAP, AT_HWCAP2)` for this machine.
pub fn detect() -> (u64, u64) {
    // Every Apple Silicon CPU has FP and Advanced SIMD.
    #[allow(unused_mut)]
    let (mut hwcap, mut hwcap2) = (h1::FP | h1::ASIMD, 0u64);
    #[cfg(target_os = "macos")]
    for &(name, b1, b2) in FEATURES {
        if sysctl_flag(name) {
            hwcap |= b1;
            hwcap2 |= b2;
        }
    }
    (hwcap, hwcap2)
}

/// What a guest reading `CTR_EL0` gets: macOS traps the read at EL0, which
/// Linux allows, so the backend emulates it. The value is Apple Silicon's as
/// Linux reports it there (64-byte instruction and data cache lines, PIPT
/// instruction cache), minus the `IDC` and `DIC` bits that let a program skip
/// cache maintenance: the full maintenance it does instead is allowed at EL0
/// on macOS, so code it writes is always made visible to instruction fetch.
pub const CTR_EL0: u64 = 0x8444_c004;

/// Whether `word` is `mrs <Xt>, ctr_el0`; then the low five bits are `Xt`.
pub fn is_mrs_ctr_el0(word: u32) -> bool {
    word & 0xffff_ffe0 == 0xd53b_0020
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_mrs_ctr_el0() {
        assert!(is_mrs_ctr_el0(0xd53b_0022)); // mrs x2, ctr_el0
        assert!(is_mrs_ctr_el0(0xd53b_003f)); // mrs xzr, ctr_el0
        assert!(!is_mrs_ctr_el0(0xd53b_00e0)); // mrs x0, dczid_el0
        assert!(!is_mrs_ctr_el0(0xd51b_0020)); // msr
    }
}
