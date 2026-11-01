// x18 must survive preemption. Spins without system calls, checking x18,
// then exits 0 if it was preserved and 1 if not.
    .text
    .globl _start
_start:
    movz    x18, #0x1818
    movk    x18, #0x1818, lsl #48
    mov     x10, x18
    movz    x19, #0x4000, lsl #16   // about a second of work
spin:
    cmp     x18, x10
    b.ne    lost
    subs    x19, x19, #1
    b.ne    spin
    mov     x0, #0
    b       exit
lost:
    mov     x0, #1
exit:
    mov     x8, #94                 // exit_group
    svc     #0
