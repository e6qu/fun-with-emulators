// Register state that Linux preserves across system calls and preemption.
// Exit status: 0 = all preserved, 1 = x18 lost, 2 = TPIDR_EL0 lost,
// 3 = another register lost.
    .text
    .globl _start
_start:
    movz    x18, #0x1818
    movk    x18, #0x1818, lsl #48
    movz    x9, #0x7e57
    movk    x9, #0xcafe, lsl #32
    msr     tpidr_el0, x9
    mov     x19, #20000             // iterations

loop:
    mov     x1, #1
    mov     x2, #2
    mov     x3, #3
    mov     x4, #4
    mov     x5, #5
    mov     x6, #6
    mov     x7, #7
    mov     x9, #9
    mov     x15, #15
    mov     x17, #17
    mov     x8, #124                // sched_yield
    svc     #0

    movz    x10, #0x1818
    movk    x10, #0x1818, lsl #48
    cmp     x18, x10
    b.ne    lost_x18
    mrs     x10, tpidr_el0
    movz    x11, #0x7e57
    movk    x11, #0xcafe, lsl #32
    cmp     x10, x11
    b.ne    lost_tpidr
    mov     x12, #124
    cmp     x1, #1
    ccmp    x2, #2, #0, eq
    ccmp    x3, #3, #0, eq
    ccmp    x4, #4, #0, eq
    ccmp    x5, #5, #0, eq
    ccmp    x6, #6, #0, eq
    ccmp    x7, #7, #0, eq
    ccmp    x8, x12, #0, eq
    ccmp    x9, #9, #0, eq
    ccmp    x15, #15, #0, eq
    ccmp    x17, #17, #0, eq
    b.ne    lost_other
    subs    x19, x19, #1
    b.ne    loop

    mov     x0, #0
    b       exit
lost_x18:
    mov     x0, #1
    b       exit
lost_tpidr:
    mov     x0, #2
    b       exit
lost_other:
    mov     x0, #3
exit:
    mov     x8, #94                 // exit_group
    svc     #0
