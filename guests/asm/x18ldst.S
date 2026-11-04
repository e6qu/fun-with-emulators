// x18 through the remaining load/store addressing modes: unscaled, register
// offset, pre/post-index (non-sp base), load/store pair (register and sp
// base), and SIMD structure loads and stores with x18 as the base, across
// preemption. Exit 0 if x18 is preserved, 1 otherwise.
    .text
    .globl _start
_start:
    movz    x18, #0x1818
    movk    x18, #0x1818, lsl #48
    mov     x10, x18                // sentinel copy
    adr     x1, buf

    // unscaled store/reload
    stur    x18, [x1, #0]
    movz    x18, #0
    ldur    x18, [x1, #0]
    cmp     x18, x10
    b.ne    fail

    // register-offset store/reload
    mov     x2, #8
    str     x18, [x1, x2]
    movz    x18, #0
    ldr     x18, [x1, x2]
    cmp     x18, x10
    b.ne    fail

    // pre-index store, post-index reload (base x1 moves and returns)
    str     x18, [x1, #16]!
    movz    x18, #0
    ldr     x18, [x1], #-16
    cmp     x18, x10
    b.ne    fail

    // pair store/reload with a register base
    stp     x18, x10, [x1]
    movz    x18, #0
    ldp     x3, x18, [x1]
    cmp     x18, x10
    b.ne    fail

    // pair store/reload with an sp base (exercises the imm7 adjustment)
    sub     sp, sp, #16
    stp     x18, x10, [sp]
    movz    x18, #0
    ldp     x3, x18, [sp]
    add     sp, sp, #16
    cmp     x18, x10
    b.ne    fail

    // SIMD structure stores and loads with x18 as the base: plain, and
    // post-index by an immediate and by a register (writing x18 back).
    mov     x11, x18                // the sentinel, also in a GPR for checks
    adr     x18, buf
    mov     x12, x18
    dup     v0.2d, x11
    st1     {v0.2d}, [x18]
    ld1     {v1.2d}, [x18], #16
    sub     x13, x18, x12
    cmp     x13, #16                // written back
    b.ne    fail
    mov     x3, #16
    st1     {v1.2d}, [x18], x3
    sub     x13, x18, x12
    cmp     x13, #32
    b.ne    fail
    ld1     {v2.2d}, [x12]
    umov    x13, v2.d[1]
    cmp     x13, x11
    b.ne    fail
    ldr     x13, [x12, #24]         // the second store landed after the first
    cmp     x13, x11
    b.ne    fail
    mov     x18, x10

    // spin to be preempted
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
    .balign 16
buf:
    .skip   64
