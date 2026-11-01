//! Checks of host behaviour the native backend relies on (macOS arm64).

#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use fwe_kernel::host::reserve_fixed;

/// The guest thread pointer slot is addressed as the TSD base from
/// `TPIDRRO_EL0` (low 3 bits masked) plus the slot offset, and is the value
/// `pthread_getspecific` sees.
#[test]
fn thread_pointer_slot_matches_pthread_tsd() {
    let slot = fwe_native::thread_pointer_slot();
    let key = (slot / 8) as libc::pthread_key_t;
    let value = 0x1234_5678_9abc_def0u64;
    // SAFETY: setting this thread's value for our key.
    unsafe { libc::pthread_setspecific(key, value as *const libc::c_void) };
    let tsd: u64;
    // SAFETY: reading the read-only EL0 thread register.
    unsafe { core::arch::asm!("mrs {}, tpidrro_el0", out(reg) tsd) };
    // SAFETY: the TSD array is this thread's and holds our key.
    let seen = unsafe { ((tsd & !7) as *const u64).add(key as usize).read() };
    assert_eq!(seen, value);
}

/// Report which high address ranges this process can reserve. Run with
/// `--nocapture` to see the survey.
#[test]
fn address_space_survey() {
    let len = 1 << 20;
    let mut any = false;
    for shift in 32..48 {
        for mult in [1u64, 3] {
            let addr = mult << shift;
            let result = reserve_fixed(addr, len);
            if result.is_ok() {
                any = true;
                // SAFETY: releasing the reservation just made.
                unsafe { libc::munmap(addr as *mut libc::c_void, len as usize) };
            }
            println!(
                "{addr:#016x}: {}",
                match result {
                    Ok(()) => "free".to_string(),
                    Err(e) => e.to_string(),
                }
            );
        }
    }
    assert!(any, "no high address range could be reserved");
}
