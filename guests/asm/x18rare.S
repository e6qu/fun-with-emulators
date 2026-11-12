// x18 through the rarer forms: the thread pointer and system registers,
// pointer authentication (signing, authenticated loads and branches),
// compare-and-swap of a pair, exclusive and atomic accesses on sp, loads and
// stores written back onto sp, and sp written from x18. Each is checked
// against a sentinel, then x18 is checked across preemption. Exit 0 if every
// check holds, otherwise the number of the first that failed.
    .arch   armv8.4-a
    .text
    .globl _start
_start:
    movz    x18, #0x1818
    movk    x18, #0x1818, lsl #48
    mov     x10, x18                // sentinel copy (not x18)
    mov     x20, sp                 // sp on entry

    // 1: the thread pointer through x18, both ways.
    mov     x9, #1
    mrs     x1, tpidr_el0
    msr     tpidr_el0, x18
    mrs     x2, tpidr_el0
    movz    x18, #0
    mrs     x18, tpidr_el0
    msr     tpidr_el0, x1
    cmp     x2, x10
    b.ne    fail
    cmp     x18, x10
    b.ne    fail

    // 2: system registers and a cache operation on an address in x18.
    mov     x9, #2
    cmp     x18, x18                // Z set
    mrs     x18, nzcv
    mrs     x3, nzcv
    cmp     x18, x3
    b.ne    fail
    msr     nzcv, x18
    b.ne    fail
    adr     x18, buf
    dc      cvau, x18
    adr     x3, buf
    cmp     x18, x3
    b.ne    fail
    mov     x18, x10

    // 3: pointer authentication of an address in x18, with sp and x1 as
    // modifiers.
    mov     x9, #3
    adr     x18, buf
    mov     x11, x18
    pacia   x18, sp
    autia   x18, sp
    cmp     x18, x11
    b.ne    fail
    mov     x1, #77
    pacia   x18, x1
    autia   x18, x1
    paciza  x18
    xpaci   x18
    cmp     x18, x11
    b.ne    fail
    pacga   x18, x1, sp
    pacga   x3, x1, sp
    cmp     x18, x3
    b.ne    fail
    mov     x18, x10

    // 4: authenticated branches through x18.
    mov     x9, #4
    adr     x18, 1f
    pacia   x18, x1
    braa    x18, x1
    b       fail
1:  adr     x18, called
    paciza  x18
    blraaz  x18
    cmp     x0, #42
    b.ne    fail
    mov     x18, x10

    // 5: an authenticated load into and from x18.
    mov     x9, #5
    adr     x1, buf
    str     x10, [x1]
    pacdza  x1
    movz    x18, #0
    ldraa   x18, [x1]
    cmp     x18, x10
    b.ne    fail
    adr     x18, buf
    pacdza  x18
    ldraa   x3, [x18]
    cmp     x3, x10
    b.ne    fail
    mov     x18, x10

    // 6: compare-and-swap of a pair holding x18, and of a pair at x18.
    mov     x9, #6
    adr     x0, buf
    mov     x19, #0x1919
    stp     x18, x19, [x0]
    mov     x2, #2
    mov     x3, #3
    casp    x18, x19, x2, x3, [x0]
    cmp     x18, x10                // the old value, equal
    b.ne    fail
    mov     x6, #0x1919
    cmp     x19, x6
    b.ne    fail
    ldp     x4, x5, [x0]
    cmp     x4, #2
    b.ne    fail
    cmp     x5, #3
    b.ne    fail
    mov     x18, x10
    mov     x2, #2
    mov     x3, #3
    caspal  x2, x3, x18, x19, [x0]  // stores x18, x19
    ldp     x4, x5, [x0]
    cmp     x4, x10
    b.ne    fail
    mov     x18, x0
    mov     x4, x10
    mov     x5, #0x1919
    mov     x6, #6
    mov     x7, #7
    casp    x4, x5, x6, x7, [x18]
    ldp     x4, x5, [x0]
    cmp     x4, #6
    b.ne    fail
    mov     x18, x10

    // 7: exclusive and atomic accesses on sp.
    mov     x9, #7
    sub     sp, sp, #16
    str     x10, [sp]
    movz    x18, #0
    ldxr    x18, [sp]
    clrex
    cmp     x18, x10
    b.ne    fail
    mov     x3, #1
    ldadd   x3, x18, [sp]           // x18 = the old value
    cmp     x18, x10
    b.ne    fail
    ldr     x3, [sp]
    add     x4, x10, #1
    cmp     x3, x4
    b.ne    fail
    add     sp, sp, #16
    mov     x18, x10

    // 8: loads and stores written back onto sp.
    mov     x9, #8
    mov     x29, #0x2929
    str     x18, [sp, #-16]!
    stp     x29, x18, [sp, #-32]!
    movz    x18, #0
    ldp     x3, x18, [sp], #32
    cmp     x18, x10
    b.ne    fail
    cmp     x3, x29
    b.ne    fail
    movz    x18, #0
    ldr     x18, [sp], #16
    cmp     x18, x10
    b.ne    fail
    mov     x3, sp
    cmp     x3, x20
    b.ne    fail

    // 9: sp written from x18.
    mov     x9, #9
    mov     x18, sp
    sub     sp, sp, #64
    mov     sp, x18
    mov     x3, sp
    cmp     x3, x20
    b.ne    fail
    mov     x18, #48
    sub     sp, sp, x18
    mov     x3, sp
    sub     x4, x20, #48
    cmp     x3, x4
    b.ne    fail
    add     sp, sp, x18
    sub     x18, x20, #8
    and     sp, x18, #0xfffffffffffffff0
    mov     x3, sp
    sub     x4, x20, #16
    cmp     x3, x4
    b.ne    fail
    mov     x18, #16
    adr     x3, buf
    ldr     q1, [x3]
    str     q1, [sp, #-16]!         // 16 bytes to load back
    ld1     {v0.16b}, [sp], x18
    mov     x3, sp
    sub     x4, x20, #16
    cmp     x3, x4
    b.ne    fail
    mov     sp, x20
    mov     x18, x10

    // 10: every check above left the sentinel intact; spin to be preempted.
    mov     x9, #10
    movz    x19, #0x1000, lsl #16
spin:
    cmp     x18, x10
    b.ne    fail
    subs    x19, x19, #1
    b.ne    spin

    mov     x0, #0
    b       exit
fail:
    mov     x0, x9
exit:
    mov     x8, #94                 // exit_group
    svc     #0

called:
    mov     x0, #42
    ret

    .data
    .balign 16
buf:
    .quad   0, 0
