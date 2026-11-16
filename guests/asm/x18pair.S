// The register saves and restores HotSpot's stubs make around a call, with
// x18 in a pair addressed off sp: `stp x18, xzr, [sp, #128]` (xzr, register
// 31, the pair's padding, while 31 as the base is sp), `ldp x18, xzr`,
// `stp x18, x19` and the post-indexed `ldp x18, x19, [sp], #96`. Every
// register is checked after each round, across preemption and system calls.
// Exit 0 when all are kept, otherwise 1 + the number of the register lost.
    .text
    .globl _start
_start:
    mov     x28, #2000              // rounds
round:
    // Each register its own value (x28 counts; x8 is the call number).
    .irp n, 0,1,2,3,4,5,6,7,9,10,11,12,13,14,15,16,17,19,20,21,22,23,24,25,26,27,29,30
    movz    x\n, #(0x1000 + \n)
    movk    x\n, #0x5a5a, lsl #32
    .endr
    movz    x18, #0x1818
    movk    x18, #0x5a5a, lsl #32

    sub     sp, sp, #256
    stp     x18, xzr, [sp, #128]
    stp     x18, x19, [sp, #144]
    movz    x18, #0
    ldp     x18, xzr, [sp, #128]
    bl      check
    movz    x18, #0
    ldp     x18, x19, [sp, #144]
    bl      check
    // Saved again, then restored with the pair that pops the frame.
    add     sp, sp, #160
    stp     x18, x19, [sp, #-96]!
    movz    x18, #0
    mov     x8, #124                // sched_yield, for preemption between
    svc     #0
    movz    x0, #0x1000             // the call's result replaced it
    movk    x0, #0x5a5a, lsl #32
    movz    x8, #0
    ldp     x18, x19, [sp], #96
    bl      check
    add     sp, sp, #96

    subs    x28, x28, #1
    b.ne    round
    mov     x0, #0
    mov     x8, #93
    svc     #0

// Every register as set above (x8, x28 and x30 aside).
check:
    .irp n, 0,1,2,3,4,5,6,7,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,29
    movz    x8, #(0x1000 + \n)
    .if \n == 18
    movz    x8, #0x1818
    .endif
    movk    x8, #0x5a5a, lsl #32
    cmp     x\n, x8
    b.ne    lost_\n
    .endr
    movz    x8, #0
    ret

    .irp n, 0,1,2,3,4,5,6,7,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,29
lost_\n:
    mov     x0, #(1 + \n)
    mov     x8, #93
    svc     #0
    .endr
