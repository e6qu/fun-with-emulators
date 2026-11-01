// A minimal stand-in dynamic linker: find AT_ENTRY in the auxiliary vector
// and jump to it. Enough to exercise fwe's interpreter loading and the
// AT_BASE/AT_ENTRY handoff without a real libc.
    .text
    .globl _start
_start:
    ldr     x9, [sp]                // argc
    add     x10, sp, #8             // &argv[0]
    add     x10, x10, x9, lsl #3    // skip argv entries
    add     x10, x10, #8            // skip the argv NULL -> &envp[0]
env_loop:
    ldr     x11, [x10], #8          // envp[i]++
    cbnz    x11, env_loop           // until NULL -> x10 at auxv
aux_loop:
    ldr     x12, [x10], #8          // a_type
    ldr     x13, [x10], #8          // a_val
    cmp     x12, #9                 // AT_ENTRY
    b.eq    found
    cbnz    x12, aux_loop           // until AT_NULL
    mov     x0, #127                // AT_ENTRY not found
    mov     x8, #94
    svc     #0
found:
    br      x13                     // enter the executable
