// x18 read by compare/test branches (cbz/cbnz/tbz/tbnz) must use the preserved
// value, across preemption. Exit 0 if all branches go the right way, else 1.
    .text
    .globl _start
_start:
    movz    x18, #0x1818
    movk    x18, #0x1818, lsl #48   // nonzero; bit3 set, bit0 clear

    // spin: each iteration, cbnz and tbnz must both see x18 nonzero / bit3 set
    movz    x19, #0x1000, lsl #16
loop:
    cbnz    x18, c1
    b       fail
c1:
    tbnz    x18, #3, c2
    b       fail
c2:
    tbz     x18, #0, c3             // bit0 is clear -> taken
    b       fail
c3:
    subs    x19, x19, #1
    b.ne    loop

    // cbz on a zero x18 must be taken
    movz    x18, #0
    cbz     x18, ok
    b       fail
ok:
    mov     x0, #0
    b       exit
fail:
    mov     x0, #1
exit:
    mov     x8, #94                 // exit_group
    svc     #0
