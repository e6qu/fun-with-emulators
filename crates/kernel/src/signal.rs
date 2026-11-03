//! Signal delivery: building the arm64 `rt_sigframe`, entering a guest
//! handler, and restoring on `rt_sigreturn`.
//!
//! Only the general-purpose registers, stack pointer, pc and pstate are saved
//! and restored across a handler. Floating-point and vector state is not yet
//! preserved, so a handler that clobbers it corrupts the interrupted context;
//! this is tracked on the roadmap.

use crate::{Kernel, Platform, Regs};
use fwe_abi::{Sigaction, Stack, signal};

// Offsets within `struct rt_sigframe` on arm64 (`siginfo` then `ucontext`).
const SIGINFO_SIZE: u64 = 128;
/// `si_addr` within `siginfo` (the `_sigfault` member).
const SI_ADDR_OFF: u64 = 16;
/// `ucontext` start.
const UC_OFF: u64 = SIGINFO_SIZE;
/// `uc_stack` within `ucontext`.
const UC_STACK_OFF: u64 = UC_OFF + 16;
/// `uc_sigmask` within `ucontext`.
const UC_SIGMASK_OFF: u64 = UC_OFF + 40;
/// `uc_mcontext` (a `struct sigcontext`) within `ucontext`: after the
/// 8-byte `uc_flags`, `uc_link`, the 24-byte `uc_stack`, the 8-byte
/// `uc_sigmask` and the 120 bytes padding it to 1024 bits, rounded up to the
/// 16-byte alignment `sigcontext` carries (its `__reserved` is aligned 16).
const UC_MCONTEXT_OFF: u64 = UC_OFF + 176;
/// `regs[31]` within `sigcontext` (after `fault_address`).
const MC_REGS_OFF: u64 = UC_MCONTEXT_OFF + 8;
const MC_SP_OFF: u64 = MC_REGS_OFF + 31 * 8;
const MC_PC_OFF: u64 = MC_SP_OFF + 8;
const MC_PSTATE_OFF: u64 = MC_PC_OFF + 8;
/// `__reserved` within `sigcontext`, holding FP/SVE records: 16-byte aligned,
/// so 8 bytes of padding follow `pstate`.
const MC_RESERVED_OFF: u64 = UC_MCONTEXT_OFF + 288;
/// Total frame size: through the 4096-byte `__reserved` area.
const FRAME_SIZE: u64 = MC_RESERVED_OFF + 4096;

/// FP-context magic that marks the end of the reserved records (none present).
const FPSIMD_MAGIC_NULL: u64 = 0;

/// Guest addresses are host addresses; callers pass addresses inside the
/// guest stack frame they are building or reading.
unsafe fn poke(addr: u64, val: u64) {
    // SAFETY: the caller guarantees `addr` is a writable guest address.
    unsafe { (addr as *mut u64).write_unaligned(val) }
}
unsafe fn poke32(addr: u64, val: i32) {
    // SAFETY: the caller guarantees `addr` is a writable guest address.
    unsafe { (addr as *mut i32).write_unaligned(val) }
}
unsafe fn peek(addr: u64) -> u64 {
    // SAFETY: the caller guarantees `addr` is a readable guest address.
    unsafe { (addr as *const u64).read_unaligned() }
}

fn align_down(x: u64, a: u64) -> u64 {
    x & !(a - 1)
}

impl<P: Platform> Kernel<P> {
    /// Mark `sig` pending against this process (a self-directed signal).
    pub(crate) fn raise_pending(&mut self, sig: u64) {
        if (1..=signal::NSIG).contains(&sig) {
            self.pending |= 1 << (sig - 1);
        }
    }

    /// Deliver one ready pending signal, if any, before returning to the guest.
    pub fn deliver_pending(&mut self, regs: &mut Regs) {
        let ready = self.pending & !self.sigmask;
        if ready == 0 {
            return;
        }
        let sig = ready.trailing_zeros() as u64 + 1;
        self.pending &= !(1 << (sig - 1));
        let action = self.sigactions[(sig - 1) as usize];
        match action.handler {
            h if h == signal::SIG_IGN => {}
            h if h == signal::SIG_DFL => {
                if signal::default_is_terminate(sig) {
                    self.terminate_by(sig);
                }
            }
            _ => {
                self.deliver_to_handler(regs, sig, signal::SI_USER, 0);
            }
        }
    }

    /// Terminate the process as killed by `sig`.
    pub(crate) fn terminate_by(&mut self, sig: u64) -> ! {
        match crate::host::signal_to_host(sig) {
            Some(h) => self.platform.kill_self(h),
            None => self.platform.exit(128 + sig as i32),
        }
    }

    /// Build a signal frame and point `regs` at the handler for `sig`.
    /// Returns `false` without changing `regs` if `sig` has no handler.
    pub(crate) fn deliver_to_handler(
        &mut self,
        regs: &mut Regs,
        sig: u64,
        si_code: i32,
        fault_addr: u64,
    ) -> bool {
        let action = self.sigactions[(sig - 1) as usize];
        if action.handler == signal::SIG_DFL || action.handler == signal::SIG_IGN {
            return false;
        }

        // Choose the stack: the alternate stack if requested and available.
        // A handler already running on the alternate stack keeps using it
        // from its current sp, as Linux does; starting over from the top would
        // overwrite the live frame beneath it.
        let on_altstack = action.flags & signal::SA_ONSTACK != 0
            && self.altstack.ss_flags & fwe_abi::signal::SS_DISABLE == 0;
        let alt_top = self.altstack.ss_sp.wrapping_add(self.altstack.ss_size);
        let already_on_alt = self.altstack.ss_flags & fwe_abi::signal::SS_DISABLE == 0
            && regs.sp >= self.altstack.ss_sp
            && regs.sp < alt_top;
        let base_sp = if on_altstack && !already_on_alt { alt_top } else { regs.sp };
        // If there is no room for a frame (e.g. a stack-overflow fault leaves sp
        // below FRAME_SIZE, or the chosen stack base is tiny), we cannot deliver
        // on this stack. Report it as undelivered rather than crashing `fwe`;
        // the caller then takes the default action and prints diagnostics.
        let frame = match base_sp.checked_sub(FRAME_SIZE) {
            Some(v) => align_down(v, 16),
            None => return false,
        };

        let old_mask = self.sigmask;
        // SAFETY: `frame` is a writable region on the guest stack.
        unsafe {
            // zero the whole frame, then fill the fields we define.
            std::ptr::write_bytes(frame as *mut u8, 0, FRAME_SIZE as usize);
            // siginfo
            poke32(frame, sig as i32); // si_signo
            poke32(frame + 8, si_code); // si_code
            if fault_addr != 0 {
                poke(frame + SI_ADDR_OFF, fault_addr);
            }
            // ucontext
            poke(frame + UC_STACK_OFF, self.altstack.ss_sp);
            poke32(frame + UC_STACK_OFF + 8, self.altstack.ss_flags);
            poke(frame + UC_STACK_OFF + 16, self.altstack.ss_size);
            poke(frame + UC_SIGMASK_OFF, old_mask);
            // sigcontext
            poke(frame + UC_MCONTEXT_OFF, fault_addr); // fault_address
            for (i, &v) in regs.x.iter().enumerate() {
                poke(frame + MC_REGS_OFF + i as u64 * 8, v);
            }
            poke(frame + MC_SP_OFF, regs.sp);
            poke(frame + MC_PC_OFF, regs.pc);
            poke(frame + MC_PSTATE_OFF, regs.pstate);
            poke(frame + MC_RESERVED_OFF, FPSIMD_MAGIC_NULL);
        }

        // Mask this and the handler's extra signals while it runs.
        self.sigmask |= action.mask;
        if action.flags & signal::SA_NODEFER == 0 {
            self.sigmask |= 1 << (sig - 1);
        }
        if action.flags & signal::SA_RESETHAND != 0 {
            self.sigactions[(sig - 1) as usize] = Sigaction::default();
        }

        // Enter the handler.
        let siginfo = action.flags & signal::SA_SIGINFO != 0;
        regs.x[0] = sig;
        regs.x[1] = if siginfo { frame } else { 0 };
        regs.x[2] = if siginfo { frame + UC_OFF } else { 0 };
        regs.x[30] = if action.flags & signal::SA_RESTORER != 0 {
            action.restorer
        } else {
            self.sigreturn_tramp
        };
        regs.sp = frame;
        regs.pc = action.handler;
        regs.pstate = 0;
        true
    }

    /// Restore `regs` from the signal frame at `regs.sp` (the `rt_sigreturn`
    /// system call).
    pub(crate) fn sys_rt_sigreturn(&mut self, regs: &mut Regs) {
        let frame = regs.sp;
        // SAFETY: the guest's sp points at the frame we built for the handler.
        unsafe {
            for i in 0..31 {
                regs.x[i] = peek(frame + MC_REGS_OFF + i as u64 * 8);
            }
            regs.sp = peek(frame + MC_SP_OFF);
            regs.pc = peek(frame + MC_PC_OFF);
            regs.pstate = peek(frame + MC_PSTATE_OFF);
            self.sigmask = peek(frame + UC_SIGMASK_OFF);
            let ss_sp = peek(frame + UC_STACK_OFF);
            let ss_flags = peek(frame + UC_STACK_OFF + 8) as i32;
            let ss_size = peek(frame + UC_STACK_OFF + 16);
            self.altstack = Stack { ss_sp, ss_flags, _pad: 0, ss_size };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Brk, Tracer};

    /// The computed frame offsets match the arm64 kernel layout.
    #[test]
    fn frame_offsets() {
        // `offsetof(struct rt_sigframe, uc.uc_mcontext)` and friends on arm64
        // Linux; glibc's `getcontext` stores `x18`/`x19` at
        // `uc_mcontext + 8 + 18 * 8` = 328 from `ucontext`, which is 456 here.
        assert_eq!(UC_MCONTEXT_OFF, 304);
        assert_eq!(MC_REGS_OFF, 312);
        assert_eq!(MC_REGS_OFF + 18 * 8 - UC_OFF, 328);
        assert_eq!(MC_SP_OFF, 560);
        assert_eq!(MC_PC_OFF, 568);
        assert_eq!(MC_PSTATE_OFF, 576);
        assert_eq!(MC_RESERVED_OFF, 592);
        assert_eq!(FRAME_SIZE, 4688);
    }

    struct NoPlatform;
    impl Platform for NoPlatform {
        fn prepare_exec(&mut self, _a: u64, _l: u64) -> Result<(), i32> {
            Ok(())
        }
        fn exit(&mut self, code: i32) -> ! {
            panic!("exit({code})")
        }
        fn exit_thread(&mut self, code: i32) -> ! {
            panic!("exit_thread({code})")
        }
        fn kill_self(&mut self, sig: libc::c_int) -> ! {
            panic!("killed by {sig}")
        }
    }

    const HANDLER: u64 = 0x4444_0000;
    const TRAMP: u64 = 0x5555_0000;

    fn kernel() -> Kernel<NoPlatform> {
        let mut k = Kernel::new(
            NoPlatform,
            16384,
            Brk { start: 0, current: 0, limit: 0 },
            None,
            Tracer::default(),
        );
        k.set_sigreturn_trampoline(TRAMP);
        k
    }

    #[test]
    fn delivers_handler_and_restores_on_sigreturn() {
        let mut k = kernel();
        let act = Sigaction { handler: HANDLER, flags: signal::SA_SIGINFO, restorer: 0, mask: 0 };
        k.sigactions[(signal::SIGUSR1 - 1) as usize] = act;

        // A guest stack to build the frame on.
        let stack = vec![0u8; 64 * 1024];
        let top = (stack.as_ptr() as u64 + stack.len() as u64) & !15;
        let mut regs = Regs { sp: top, pc: 0x1000, ..Regs::default() };
        regs.x[5] = 0xdead_beef;
        regs.x[30] = 0xcafe; // caller's lr, must be saved and restored

        k.raise_pending(signal::SIGUSR1);
        k.deliver_pending(&mut regs);

        // Entered the handler with the Linux calling convention.
        assert_eq!(regs.pc, HANDLER);
        assert_eq!(regs.x[0], signal::SIGUSR1);
        let frame = regs.sp;
        assert_eq!(frame % 16, 0);
        assert!(frame < top && top - frame >= FRAME_SIZE);
        assert_eq!(regs.x[1], frame); // siginfo
        assert_eq!(regs.x[2], frame + UC_OFF); // ucontext
        assert_eq!(regs.x[30], TRAMP); // return to the sigreturn trampoline
        // The handler runs with the signal masked.
        assert_eq!(k.sigmask, 1 << (signal::SIGUSR1 - 1));
        // Pending bit cleared.
        assert_eq!(k.pending, 0);

        // Now return from the handler.
        regs.x[8] = fwe_abi::nr::RT_SIGRETURN;
        k.enter_syscall(&mut regs);
        assert_eq!(regs.pc, 0x1000);
        assert_eq!(regs.sp, top);
        assert_eq!(regs.x[5], 0xdead_beef);
        assert_eq!(regs.x[30], 0xcafe);
        assert_eq!(k.sigmask, 0);
    }

    /// A second signal delivered while a handler runs on the alternate stack
    /// builds its frame below the running handler's sp, not over it.
    #[test]
    fn nested_delivery_stays_below_live_altstack_frame() {
        let mut k = kernel();
        let act = Sigaction { handler: HANDLER, flags: signal::SA_ONSTACK, restorer: 0, mask: 0 };
        k.sigactions[(signal::SIGUSR1 - 1) as usize] = act;
        k.sigactions[(signal::SIGUSR2 - 1) as usize] = act;
        let alt = vec![0u8; 64 * 1024];
        let alt_base = alt.as_ptr() as u64;
        k.altstack = Stack { ss_sp: alt_base, ss_flags: 0, _pad: 0, ss_size: alt.len() as u64 };

        let mut regs = Regs { sp: 0x9000, pc: 0x1000, ..Regs::default() };
        k.raise_pending(signal::SIGUSR1);
        k.deliver_pending(&mut regs);
        let first = regs.sp;
        assert!(first >= alt_base && first < alt_base + alt.len() as u64);

        // Pretend the handler used some stack, then a second signal arrives.
        regs.sp = first - 256;
        k.raise_pending(signal::SIGUSR2);
        k.deliver_pending(&mut regs);
        let second = regs.sp;
        assert!(second + FRAME_SIZE <= first - 256, "second frame {second:#x} overlaps {first:#x}");
    }

    #[test]
    fn ignored_signal_is_dropped() {
        let mut k = kernel();
        k.sigactions[(signal::SIGUSR1 - 1) as usize].handler = signal::SIG_IGN;
        let mut regs = Regs { sp: 0x9000, pc: 0x1000, ..Regs::default() };
        k.raise_pending(signal::SIGUSR1);
        k.deliver_pending(&mut regs);
        assert_eq!(regs.pc, 0x1000); // unchanged
        assert_eq!(k.pending, 0);
    }

    #[test]
    fn blocked_signal_stays_pending() {
        let mut k = kernel();
        k.sigactions[(signal::SIGUSR1 - 1) as usize].handler = HANDLER;
        k.sigmask = 1 << (signal::SIGUSR1 - 1);
        let mut regs = Regs { sp: 0x9000, pc: 0x1000, ..Regs::default() };
        k.raise_pending(signal::SIGUSR1);
        k.deliver_pending(&mut regs);
        assert_eq!(regs.pc, 0x1000); // not delivered
        assert_eq!(k.pending, 1 << (signal::SIGUSR1 - 1)); // still pending
    }
}
