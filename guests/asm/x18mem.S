// x18 must survive when spilled to memory and reloaded, across preemption.
// Covers loads/stores with a non-sp base and with an sp base (a stack spill).
// Exits 0 if x18 is preserved throughout, 1 otherwise.
    .text
    .globl _start
_start:
    movz    x18, #0x1818
    movk    x18, #0x1818, lsl #48
    mov     x10, x18                // sentinel copy (not x18)

    // Store to a .bss buffer via a register base, clobber x18, reload.
    adr     x1, buf
    str     x18, [x1]
    movz    x18, #0
    ldr     x18, [x1]
    cmp     x18, x10
    b.ne    fail

    // Spill to the stack (sp base), clobber x18, reload.
    sub     sp, sp, #16
    str     x18, [sp, #0]
    movz    x18, #0
    ldr     x18, [sp, #0]
    add     sp, sp, #16
    cmp     x18, x10
    b.ne    fail

    // Spin without system calls to be preempted, re-checking x18.
    movz    x19, #0x2000, lsl #16
spin:
    cmp     x18, x10
    b.ne    fail
    subs    x19, x19, #1
    b.ne    spin

    mov     x0, #0
    b       exit
fail:
    mov     x0, #1
exit:
    mov     x8, #94                 // exit_group
    svc     #0

    .bss
    .balign 8
buf:
    .skip   8
