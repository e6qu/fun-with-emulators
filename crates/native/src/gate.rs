//! The system-call gate: guest code calls fwe directly for a system call.
//!
//! A rewritten `svc #0` branches to a stub of its own
//! ([`crate::rewrite`]), which saves `x30` and `x0` below the guest's `sp`
//! and calls [`fwe_gate`]. (Where the guest's `sp` takes no store, as at
//! musl's thread exit, which unmaps its own stack before `exit`, that store
//! faults, and the fault handler runs the call as the trap does.) The gate saves the guest's registers into this thread's
//! [`Block`], switches to the thread's gate stack and calls the Rust half
//! (`trap::fwe_gate_call`), which runs the call. When the call changed
//! nothing but `x0` and no signal is to be delivered, the gate restores the
//! registers and returns to the stub, which goes on past the site: no host
//! exception, no signal, no change of the host's signal mask (the guest's
//! is already in force). Every other outcome (a call that changes `pc`,
//! `sp` or the mask, a signal to deliver, a traced or filtered call, and
//! the calls fwe runs outside the kernel lock) takes the trap: the gate
//! executes `brk #GATE_IMM`, and the `SIGTRAP` handler takes the guest's
//! state from the block and goes on as for a trapped `svc`.
//!
//! A host signal that lands in the gate's own instructions, or while the
//! Rust half runs (the block's `active` flag), lands in fwe's code: it is
//! recorded, and the call delivers it as it ends. One that lands in the
//! gate's way out is recorded too, and the way out starts again
//! ([`rewind`]), which sees the signal count changed and takes the trap.

use fwe_kernel::Regs;
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};

/// Immediate of the `brk` the gate takes for everything but a plain call.
pub const GATE_IMM: u32 = 0x4c5a;

/// `brk #GATE_IMM`.
pub const GATE_TRAP: u32 = 0xd420_0000 | (GATE_IMM << 5);

/// Size of each thread's gate stack.
const STACK_SIZE: usize = 1 << 20;

/// One thread's gate state, at the start of its gate mapping.
#[repr(C)]
pub struct Block {
    /// The guest's registers at the call (`pc` set by the Rust half), and
    /// after it.
    pub regs: Regs,
    /// Where the gate returns to: the stub, past its call.
    pub ret: u64,
    /// The Rust half is running (or about to take the trap).
    pub active: AtomicU64,
    /// Signals recorded for this thread, counted.
    pub signals: AtomicU64,
    /// [`Block::signals`] as the call last looked for one to deliver.
    pub seen: u64,
    /// The top of the gate stack.
    pub stack: u64,
    /// The call has run (the trap only delivers what is pending).
    pub ran: u64,
}

const _: () = assert!(std::mem::size_of::<Regs>() == 800);
const _: () = assert!(std::mem::offset_of!(Block, ret) == 800);
const _: () = assert!(std::mem::offset_of!(Block, active) == 808);
const _: () = assert!(std::mem::offset_of!(Block, signals) == 816);
const _: () = assert!(std::mem::offset_of!(Block, seen) == 824);
const _: () = assert!(std::mem::offset_of!(Block, stack) == 832);

/// Byte offset of the block's pointer in the host TSD, for the gate.
#[unsafe(no_mangle)]
static FWE_GATE_SLOT: AtomicU64 = AtomicU64::new(0);

fn key() -> libc::pthread_key_t {
    static KEY: std::sync::OnceLock<libc::pthread_key_t> = std::sync::OnceLock::new();
    *KEY.get_or_init(|| {
        let mut key: libc::pthread_key_t = 0;
        // SAFETY: creating a key without destructor; it lives forever.
        let r = unsafe { libc::pthread_key_create(&mut key, None) };
        assert_eq!(r, 0, "pthread_key_create failed");
        FWE_GATE_SLOT.store(key as u64 * 8, SeqCst);
        key
    })
}

/// This thread's block, if it has one. Async-signal-safe.
pub fn block() -> Option<&'static Block> {
    // SAFETY: reading this thread's value of fwe's key.
    let p = unsafe { libc::pthread_getspecific(key()) } as *const Block;
    // SAFETY: a block is never freed while its thread runs guest code.
    (!p.is_null()).then(|| unsafe { &*p })
}

/// Give this thread a block and gate stack, if it has none yet (a forked
/// child keeps its parent thread's, a copy). Its guest code calls the gate
/// from now on.
pub fn ensure_block() {
    if block().is_some() {
        return;
    }
    let page = crate::page_size() as usize;
    let size = page + STACK_SIZE;
    // SAFETY: a fresh mapping for the block (first page) and the stack
    // above it, for the life of the thread, as its signal stack is.
    unsafe {
        let p = libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        );
        assert_ne!(p, libc::MAP_FAILED, "allocating the gate stack failed");
        let b = p as *mut Block;
        (*b).stack = p as u64 + size as u64;
        libc::pthread_setspecific(key(), p);
    }
}

/// Whether `pc` is in the gate's own instructions. Async-signal-safe.
pub fn in_gate(pc: u64) -> bool {
    (fwe_gate as *const () as u64..fwe_gate_end as *const () as u64).contains(&pc)
}

/// A signal landed at `pc` in fwe's code: if that is the gate's way out,
/// the address to start it again from (it looks for a signal first).
pub fn rewind(pc: u64) -> Option<u64> {
    let exit = fwe_gate_exit as *const () as u64;
    (exit..fwe_gate_end as *const () as u64).contains(&pc).then_some(exit)
}

/// Whether this thread is in the gate's Rust half. Async-signal-safe.
pub fn active() -> bool {
    block().is_some_and(|b| b.active.load(SeqCst) != 0)
}

/// A signal was recorded for this thread. Async-signal-safe.
pub fn note_signal() {
    if let Some(b) = block() {
        b.signals.fetch_add(1, SeqCst);
    }
}

/// The address of the gate, which stubs call.
pub fn address() -> u64 {
    key();
    fwe_gate as *const () as u64
}

/// The system-call site whose stub returns to `ret` (the stub's branch
/// back, one word on, goes past the site).
pub fn site_of(ret: u64) -> u64 {
    // SAFETY: `ret` is in a stub fwe wrote, which is mapped.
    let b = unsafe { ((ret + 4) as *const u32).read() };
    let offset = (((b & 0x03ff_ffff) << 6) as i32 >> 4) as i64;
    (ret as i64 + 4 + offset) as u64 - 4
}

unsafe extern "C" {
    /// The gate (see the module documentation); its stub calls it with the
    /// guest's `x30` and `x0` saved at `[sp]` and `[sp, #8]`.
    fn fwe_gate();
    /// The gate's way out: from here it looks for a signal, restores the
    /// guest's registers from the block and returns to the stub.
    fn fwe_gate_exit();
    /// The end of the gate's instructions.
    fn fwe_gate_end();
}

core::arch::global_asm!(
    ".text",
    ".p2align 4",
    ".globl _fwe_gate",
    "_fwe_gate:",
    // The stub saved x30 and x0 at [sp] and [sp, #8], 32 bytes below the
    // guest's sp; x1 goes beside them, a second scratch register.
    "str x1, [sp, #16]",
    "mrs x0, tpidrro_el0",
    "and x0, x0, #0xfffffffffffffff8",
    "adrp x1, _FWE_GATE_SLOT@PAGE",
    "ldr x1, [x1, _FWE_GATE_SLOT@PAGEOFF]",
    "ldr x0, [x0, x1]",
    "stp x2, x3, [x0, #16]",
    "stp x4, x5, [x0, #32]",
    "stp x6, x7, [x0, #48]",
    "stp x8, x9, [x0, #64]",
    "stp x10, x11, [x0, #80]",
    "stp x12, x13, [x0, #96]",
    "stp x14, x15, [x0, #112]",
    "stp x16, x17, [x0, #128]",
    "stp x18, x19, [x0, #144]",
    "stp x20, x21, [x0, #160]",
    "stp x22, x23, [x0, #176]",
    "stp x24, x25, [x0, #192]",
    "stp x26, x27, [x0, #208]",
    "stp x28, x29, [x0, #224]",
    "ldr x2, [sp, #8]",
    "ldr x3, [sp, #16]",
    "stp x2, x3, [x0, #0]",
    // The guest's x30, saved by the stub, and its sp above them.
    "ldr x2, [sp]",
    "str x2, [x0, #240]",
    "add x2, sp, #32",
    "str x2, [x0, #248]",
    "mrs x2, nzcv",
    "str x2, [x0, #264]",
    "str x30, [x0, #800]",
    "add x2, x0, #272",
    "stp q0, q1, [x2, #0]",
    "stp q2, q3, [x2, #32]",
    "stp q4, q5, [x2, #64]",
    "stp q6, q7, [x2, #96]",
    "stp q8, q9, [x2, #128]",
    "stp q10, q11, [x2, #160]",
    "stp q12, q13, [x2, #192]",
    "stp q14, q15, [x2, #224]",
    "stp q16, q17, [x2, #256]",
    "stp q18, q19, [x2, #288]",
    "stp q20, q21, [x2, #320]",
    "stp q22, q23, [x2, #352]",
    "stp q24, q25, [x2, #384]",
    "stp q26, q27, [x2, #416]",
    "stp q28, q29, [x2, #448]",
    "stp q30, q31, [x2, #480]",
    "mrs x3, fpsr",
    "mrs x4, fpcr",
    "str w3, [x0, #784]",
    "str w4, [x0, #788]",
    "mov x2, #1",
    "str x2, [x0, #808]",
    "ldr x2, [x0, #832]",
    "mov sp, x2",
    "bl _fwe_gate_call",
    "cbnz x0, 1f",
    ".globl _fwe_gate_exit",
    "_fwe_gate_exit:",
    "mrs x0, tpidrro_el0",
    "and x0, x0, #0xfffffffffffffff8",
    "adrp x1, _FWE_GATE_SLOT@PAGE",
    "ldr x1, [x1, _FWE_GATE_SLOT@PAGEOFF]",
    "ldr x0, [x0, x1]",
    // A signal since the call last looked: the trap delivers it.
    "ldr x1, [x0, #816]",
    "ldr x2, [x0, #824]",
    "cmp x1, x2",
    "b.ne 1f",
    "add x2, x0, #272",
    "ldp q0, q1, [x2, #0]",
    "ldp q2, q3, [x2, #32]",
    "ldp q4, q5, [x2, #64]",
    "ldp q6, q7, [x2, #96]",
    "ldp q8, q9, [x2, #128]",
    "ldp q10, q11, [x2, #160]",
    "ldp q12, q13, [x2, #192]",
    "ldp q14, q15, [x2, #224]",
    "ldp q16, q17, [x2, #256]",
    "ldp q18, q19, [x2, #288]",
    "ldp q20, q21, [x2, #320]",
    "ldp q22, q23, [x2, #352]",
    "ldp q24, q25, [x2, #384]",
    "ldp q26, q27, [x2, #416]",
    "ldp q28, q29, [x2, #448]",
    "ldp q30, q31, [x2, #480]",
    "ldr w3, [x0, #784]",
    "ldr w4, [x0, #788]",
    "msr fpsr, x3",
    "msr fpcr, x4",
    "ldr x3, [x0, #264]",
    "msr nzcv, x3",
    // Back on the guest's stack, its x30 still saved there for the stub.
    "ldr x3, [x0, #248]",
    "sub sp, x3, #32",
    "ldr x30, [x0, #800]",
    "ldp x2, x3, [x0, #16]",
    "ldp x4, x5, [x0, #32]",
    "ldp x6, x7, [x0, #48]",
    "ldp x8, x9, [x0, #64]",
    "ldp x10, x11, [x0, #80]",
    "ldp x12, x13, [x0, #96]",
    "ldp x14, x15, [x0, #112]",
    "ldp x16, x17, [x0, #128]",
    "ldp x18, x19, [x0, #144]",
    "ldp x20, x21, [x0, #160]",
    "ldp x22, x23, [x0, #176]",
    "ldp x24, x25, [x0, #192]",
    "ldp x26, x27, [x0, #208]",
    "ldp x28, x29, [x0, #224]",
    "str xzr, [x0, #808]",
    "ldp x0, x1, [x0, #0]",
    "ret",
    // Anything but a plain call: the trap takes it from the block.
    "1:",
    "brk #0x4c5a",
    ".globl _fwe_gate_end",
    "_fwe_gate_end:",
    "brk #0",
);
