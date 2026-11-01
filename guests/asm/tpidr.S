// TPIDR_EL0 must survive system calls. Exits 0 if preserved, 1 if not.
    .text
    .globl _start
_start:
    movz    x9, #0x7e57
    movk    x9, #0xcafe, lsl #32
    msr     tpidr_el0, x9
    mov     x19, #2000
loop:
    mov     x8, #124                // sched_yield
    svc     #0
    mrs     x10, tpidr_el0
    cmp     x10, x9
    b.ne    lost
    subs    x19, x19, #1
    b.ne    loop
    mov     x0, #0
    b       exit
lost:
    mov     x0, #1
exit:
    mov     x8, #94                 // exit_group
    svc     #0
