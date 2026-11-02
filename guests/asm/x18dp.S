// x18 must survive through data-processing instructions beyond moves: extract,
// conditional select, multiply-add and divide, across preemption. Exit 0 if
// x18 holds its value throughout, 1 otherwise.
    .text
    .globl _start
_start:
    movz    x18, #0x1818
    movk    x18, #0x1818, lsl #48
    mov     x10, x18                // sentinel copy

    // extr x18, x18, x18, #0  -> rotate by 0, x18 unchanged
    extr    x18, x18, x18, #0
    cmp     x18, x10
    b.ne    fail

    // csel with a true condition selects x10 into x18
    cmp     x10, x10                // sets Z (eq)
    csel    x18, x10, xzr, eq
    cmp     x18, x10
    b.ne    fail

    // madd x18, xzr, xzr, x10  -> 0*0 + x10 = x10
    madd    x18, xzr, xzr, x10
    cmp     x18, x10
    b.ne    fail

    // udiv x18, x10, #1 -> x10
    mov     x1, #1
    udiv    x18, x10, x1
    cmp     x18, x10
    b.ne    fail

    // spin without system calls to be preempted, re-checking x18
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
