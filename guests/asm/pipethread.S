// A thread blocked in read on a pipe must not stall the thread that writes to
// it: the child sleeps briefly, then writes a byte; the parent, already blocked
// in read, receives it. Exit 0 on success, 1 otherwise (a hang is a failure).
    .text
    .globl _start
_start:
    adr     x0, fds
    mov     x1, #0
    mov     x8, #59                 // pipe2
    svc     #0
    tbnz    x0, #63, fail

    movz    x0, #0x0f00             // clone flags (low half)
    movk    x0, #0x25, lsl #16      // | high half -> 0x250f00
    adr     x1, cstack_top          // child stack
    mov     x2, #0                  // parent_tid
    mov     x3, #0                  // tls
    adr     x4, ctid                // child_tid
    mov     x8, #220                // clone
    svc     #0
    tbnz    x0, #63, fail
    cbz     x0, child

    adr     x9, fds
    ldr     w0, [x9]                // read end
    adr     x1, buf
    mov     x2, #1
    mov     x8, #63                 // read: blocks until the child writes
    svc     #0
    cmp     x0, #1
    b.ne    fail
    adr     x9, buf
    ldrb    w10, [x9]
    cmp     w10, #0x5a
    b.ne    fail
    mov     x0, #0
    b       exit

child:
    adr     x0, ts                  // 50 ms, so the parent is blocked first
    mov     x1, #0
    mov     x8, #101                // nanosleep
    svc     #0
    adr     x9, fds
    ldr     w0, [x9, #4]            // write end
    adr     x1, byte
    mov     x2, #1
    mov     x8, #64                 // write
    svc     #0
    mov     x0, #0
    mov     x8, #93                 // exit (this thread)
    svc     #0

fail:
    mov     x0, #1
exit:
    mov     x8, #94                 // exit_group
    svc     #0

    .data
    .balign 8
ts:
    .quad   0, 50000000
byte:
    .byte   0x5a
    .balign 4
fds:
    .word   0, 0
buf:
    .byte   0
    .balign 4
ctid:
    .word   1

    .bss
    .balign 16
cstack:
    .skip   16384
cstack_top:
