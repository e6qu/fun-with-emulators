//! The stacks a guest thread runs fwe's code on, kept from threads that
//! ended for threads that start: its system-call gate's block and stack
//! ([`crate::gate`]) and its signal stack ([`crate::trap`]). A thread that
//! starts takes a pair, which saves two mappings and the faults on their
//! fresh pages; a thread that ends gives its pair back. Until it has, the
//! pair is still its own (it ends on one of them): a pair is taken only
//! once the thread that gave it has gone, which its Mach thread port,
//! dead then, tells.

use std::sync::Mutex;

/// A pair of stacks a thread gave as it ended: the gate's mapping (its
/// block at the start), the signal stack, and the thread's port.
struct Spare {
    gate: u64,
    alt: u64,
    port: u32,
}

static SPARES: Mutex<Vec<Spare>> = Mutex::new(Vec::new());

unsafe extern "C" {
    static mach_task_self_: u32;
    fn mach_thread_self() -> u32;
    fn mach_port_type(task: u32, name: u32, ptype: *mut u32) -> i32;
    fn mach_port_deallocate(task: u32, name: u32) -> i32;
}

/// `MACH_PORT_TYPE_DEAD_NAME`: what a thread's port is once it has ended.
const DEAD_NAME: u32 = 1 << (16 + 4);

/// A pair of stacks a thread that has ended gave back, if there is one:
/// the gate's mapping and the signal stack.
pub fn take() -> Option<(u64, u64)> {
    let mut spares = SPARES.lock().unwrap_or_else(|e| e.into_inner());
    let i = spares.iter().position(|s| {
        let mut t = 0;
        // SAFETY: asking the type of a port name this task holds.
        unsafe { mach_port_type(mach_task_self_, s.port, &mut t) == 0 && t & DEAD_NAME != 0 }
    })?;
    let s = spares.swap_remove(i);
    // SAFETY: the dead name's reference, no longer needed.
    unsafe { mach_port_deallocate(mach_task_self_, s.port) };
    Some((s.gate, s.alt))
}

/// The calling thread is ending: its stacks are for a later thread once it
/// has gone.
pub fn give(gate: u64, alt: u64) {
    // SAFETY: a send right to this thread's own port, kept until the pair
    // is taken (its name goes dead when the thread ends).
    let port = unsafe { mach_thread_self() };
    SPARES.lock().unwrap_or_else(|e| e.into_inner()).push(Spare { gate, alt, port });
}

/// In a fork child: the parent's threads' ports name nothing here, and
/// their stacks are the parent's to give (the child's copies stay unused).
pub fn forked() {
    SPARES.lock().unwrap_or_else(|e| e.into_inner()).clear();
}
