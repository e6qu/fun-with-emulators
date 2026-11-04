// epoll round trip: create a pipe, register its read end for EPOLLIN, write a
// byte, and wait. Expect epoll_pwait to return 1 event carrying EPOLLIN and the
// registered data word. Exit 0 on success, 1 on any mismatch.
    .text
    .globl _start
_start:
    // pipe2(fds, 0)
    adr     x0, fds
    mov     w1, #0
    mov     x8, #59                 // pipe2
    svc     #0
    tbnz    x0, #63, fail

    // epoll_create1(0)
    mov     w0, #0
    mov     x8, #20                 // epoll_create1
    svc     #0
    tbnz    x0, #63, fail
    mov     x20, x0                 // epfd

    // Build epoll_event { events = EPOLLIN(1); data = 0x123456789abcdef0 }:
    // on arm64 the struct is not packed, so data sits at offset 8. All 64
    // bits of it must come back.
    adr     x9, ev
    mov     w10, #1                 // EPOLLIN
    str     w10, [x9]
    movz    x11, #0xdef0
    movk    x11, #0x9abc, lsl #16
    movk    x11, #0x5678, lsl #32
    movk    x11, #0x1234, lsl #48
    str     x11, [x9, #8]

    // epoll_ctl(epfd, EPOLL_CTL_ADD(1), read_fd, &ev)
    mov     x0, x20
    mov     w1, #1                  // EPOLL_CTL_ADD
    adr     x13, fds
    ldr     w2, [x13]               // fds[0] = read end
    adr     x3, ev
    mov     x8, #21                 // epoll_ctl
    svc     #0
    tbnz    x0, #63, fail

    // write(write_fd, "x", 1)
    adr     x13, fds
    ldr     w0, [x13, #4]           // fds[1] = write end
    adr     x1, byte
    mov     x2, #1
    mov     x8, #64                 // write
    svc     #0
    cmp     x0, #1
    b.ne    fail

    // epoll_pwait(epfd, obuf, 4, 1000, 0, 0)
    mov     x0, x20
    adr     x1, obuf
    mov     w2, #4
    mov     w3, #1000
    mov     x4, #0
    mov     x5, #0
    mov     x8, #22                 // epoll_pwait
    svc     #0
    cmp     x0, #1                  // exactly one ready fd
    b.ne    fail

    // obuf[0].events must have EPOLLIN set.
    adr     x9, obuf
    ldr     w10, [x9]
    and     w10, w10, #1
    cmp     w10, #1
    b.ne    fail

    // obuf[0].data must equal what was registered.
    ldr     x11, [x9, #8]
    adr     x12, ev
    ldr     x12, [x12, #8]
    cmp     x11, x12
    b.ne    fail

    mov     x0, #0
    b       exit
fail:
    mov     x0, #1
exit:
    mov     x8, #94                 // exit_group
    svc     #0

    .section .rodata
byte:
    .asciz  "x"

    .bss
    .balign 8
fds:
    .skip   8                       // two ints: read, write
ev:
    .skip   16                      // one epoll_event
obuf:
    .skip   64                      // 4 * sizeof(epoll_event)
