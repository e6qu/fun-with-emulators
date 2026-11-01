// x18 must survive system calls. Exits 0 if preserved, 1 if not.
    .text
    .globl _start
_start:
    movz    x18, #0x1818
    movk    x18, #0x1818, lsl #48
    mov     x10, x18
    mov     x19, #2000
loop:
    mov     x8, #124                // sched_yield
    svc     #0
    cmp     x18, x10
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
