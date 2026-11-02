// x18 moved to/from floating-point registers (fmov, scvtf, fcvtzs) must use
// the preserved value, across preemption. Exit 0 on success, 1 otherwise.
    .text
    .globl _start
_start:
    movz    x18, #0x1818
    movk    x18, #0x1818, lsl #48
    mov     x10, x18

    // round-trip the bit pattern through a FP register
    fmov    d0, x18                 // from GPR
    movz    x18, #0                 // clobber
    fmov    x18, d0                 // to GPR
    cmp     x18, x10
    b.ne    fail

    // integer<->float conversions
    movz    x18, #42
    scvtf   d1, x18                 // d1 = 42.0 (reads x18)
    movz    x18, #0
    fcvtzs  x18, d1                 // x18 = 42 (writes x18)
    cmp     x18, #42
    b.ne    fail

    // spin, round-tripping x18 through a FP register each iteration
    mov     x18, x10
    movz    x19, #0x1000, lsl #16
spin:
    fmov    d0, x18
    fmov    x18, d0
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
