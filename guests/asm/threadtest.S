// Clone a thread that writes a shared counter and exits; the parent joins via
// the CLONE_CHILD_CLEARTID futex, then checks the counter. Exit 0 on success.
    .text
    .globl _start
_start:
    movz    x0, #0x0f00             // clone flags (low half)
    movk    x0, #0x25, lsl #16      // | high half -> 0x250f00
    adr     x1, cstack_top          // child stack
    mov     x2, #0                  // parent_tid
    mov     x3, #0                  // tls
    adr     x4, ctid                // child_tid (cleared on exit)
    mov     x8, #220                // clone
    svc     #0
    tbnz    x0, #63, fail
    cbz     x0, child

parent_wait:
    adr     x0, ctid
    mov     x1, #128                // FUTEX_WAIT | FUTEX_PRIVATE_FLAG
    mov     x2, #1                  // expected sentinel value
    mov     x3, #0                  // no timeout
    mov     x8, #98                 // futex
    svc     #0
    adr     x9, ctid
    ldr     w10, [x9]
    cmp     w10, #1
    b.eq    parent_wait             // spurious wake: still running
    adr     x9, counter
    ldr     w10, [x9]
    movz    w11, #0x1234
    cmp     w10, w11
    b.ne    fail
    mov     x0, #0
    b       exit

child:
    adr     x9, counter
    movz    w10, #0x1234
    str     w10, [x9]
    mov     x0, #0
    mov     x8, #93                 // exit (this thread)
    svc     #0

fail:
    mov     x0, #1
exit:
    mov     x8, #94                 // exit_group
    svc     #0

    .data
    .balign 4
counter:
    .word   0
ctid:
    .word   1                       // join sentinel

    .bss
    .balign 16
cstack:
    .skip   16384
cstack_top:
