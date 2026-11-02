// socketpair round trip: create a connected AF_UNIX stream pair, write "hi!"
// to one end and read it back from the other. Exit 0 on success, 1 otherwise.
    .text
    .globl _start
_start:
    // socketpair(AF_UNIX(1), SOCK_STREAM(1), 0, sv)
    mov     x0, #1
    mov     x1, #1
    mov     x2, #0
    adr     x3, sv
    mov     x8, #199                // socketpair
    svc     #0
    tbnz    x0, #63, fail

    // write(sv[0], msg, 3)
    adr     x9, sv
    ldr     w0, [x9]
    adr     x1, msg
    mov     x2, #3
    mov     x8, #64                 // write
    svc     #0
    cmp     x0, #3
    b.ne    fail

    // read(sv[1], buf, 8) -> 3 bytes
    adr     x9, sv
    ldr     w0, [x9, #4]
    adr     x1, buf
    mov     x2, #8
    mov     x8, #63                 // read
    svc     #0
    cmp     x0, #3
    b.ne    fail

    // buf == "hi!"
    adr     x9, buf
    adr     x10, msg
    mov     x11, #3
cmp_loop:
    ldrb    w12, [x9], #1
    ldrb    w13, [x10], #1
    cmp     w12, w13
    b.ne    fail
    subs    x11, x11, #1
    b.ne    cmp_loop

    mov     x0, #0
    b       exit
fail:
    mov     x0, #1
exit:
    mov     x8, #94                 // exit_group
    svc     #0

msg:
    .asciz  "hi!"

    .bss
    .balign 8
sv:
    .skip   8
buf:
    .skip   8
