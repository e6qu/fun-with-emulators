// x18 as a PC-relative destination (adr) and as an indirect-branch target
// (blr/br), across preemption. Exit 0 on success, 1 otherwise.
    .text
    .globl _start
_start:
    // adr writes x18 with a PC-relative address; load through it and check.
    adr     x18, val
    ldr     x0, [x18]
    movz    x1, #0xBEEF
    movk    x1, #0xDEAD, lsl #16
    cmp     x0, x1
    b.ne    fail

    // blr through x18 in a loop (to be preempted); func sets x21 = 0x55.
    movz    x19, #0x800, lsl #16
ploop:
    adr     x18, func
    blr     x18
    cmp     x21, #0x55
    b.ne    fail
    movz    x21, #0                 // reset for next iteration
    subs    x19, x19, #1
    b.ne    ploop

    // br (tail jump) through x18.
    adr     x18, cont
    br      x18
    b       fail                    // skipped
cont:
    mov     x0, #0
    b       exit
func:
    movz    x21, #0x55
    ret
fail:
    mov     x0, #1
exit:
    mov     x8, #94                 // exit_group
    svc     #0

    .section .rodata
    .balign 8
val:
    .quad   0x00000000DEADBEEF
