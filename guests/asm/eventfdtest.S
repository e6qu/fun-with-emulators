// eventfd through epoll: register a non-blocking eventfd for EPOLLIN, confirm
// it is not ready while the counter is zero, write 5, confirm epoll reports it
// readable with the registered data word, then read the counter back as 5.
// Exit 0 on success, 1 on any mismatch.
    .text
    .globl _start
_start:
    // efd = eventfd2(0, EFD_NONBLOCK)
    mov     x0, #0
    mov     w1, #0x800              // EFD_NONBLOCK (O_NONBLOCK)
    mov     x8, #19                 // eventfd2
    svc     #0
    tbnz    x0, #63, fail
    mov     x19, x0                 // efd

    // ep = epoll_create1(0)
    mov     w0, #0
    mov     x8, #20                 // epoll_create1
    svc     #0
    tbnz    x0, #63, fail
    mov     x20, x0                 // epfd

    // ev = { events = EPOLLIN(1); data = 0xABCD }
    adr     x9, ev
    mov     w10, #1
    str     w10, [x9]
    mov     x11, #0xABCD
    str     x11, [x9, #8]           // data at offset 8 (arm64 does not pack)

    // epoll_ctl(ep, EPOLL_CTL_ADD(1), efd, &ev)
    mov     x0, x20
    mov     w1, #1
    mov     x2, x19
    adr     x3, ev
    mov     x8, #21                 // epoll_ctl
    svc     #0
    tbnz    x0, #63, fail

    // epoll_pwait(ep, obuf, 4, 0, 0, 0) -> 0 (counter is zero)
    mov     x0, x20
    adr     x1, obuf
    mov     w2, #4
    mov     w3, #0
    mov     x4, #0
    mov     x5, #0
    mov     x8, #22                 // epoll_pwait
    svc     #0
    cmp     x0, #0
    b.ne    fail

    // write(efd, &5, 8)
    adr     x9, wbuf
    mov     x10, #5
    str     x10, [x9]
    mov     x0, x19
    adr     x1, wbuf
    mov     x2, #8
    mov     x8, #64                 // write
    svc     #0
    cmp     x0, #8
    b.ne    fail

    // epoll_pwait(ep, obuf, 4, 1000, 0, 0) -> 1
    mov     x0, x20
    adr     x1, obuf
    mov     w2, #4
    mov     w3, #1000
    mov     x4, #0
    mov     x5, #0
    mov     x8, #22                 // epoll_pwait
    svc     #0
    cmp     x0, #1
    b.ne    fail

    // obuf[0].events has EPOLLIN; obuf[0].data == 0xABCD
    adr     x9, obuf
    ldr     w10, [x9]
    and     w10, w10, #1
    cmp     w10, #1
    b.ne    fail
    ldr     x11, [x9, #8]
    mov     x12, #0xABCD
    cmp     x11, x12
    b.ne    fail

    // read(efd, rbuf, 8) -> 8, counter value 5
    mov     x0, x19
    adr     x1, rbuf
    mov     x2, #8
    mov     x8, #63                 // read
    svc     #0
    cmp     x0, #8
    b.ne    fail
    adr     x9, rbuf
    ldr     x10, [x9]
    cmp     x10, #5
    b.ne    fail

    mov     x0, #0
    b       exit
fail:
    mov     x0, #1
exit:
    mov     x8, #94                 // exit_group
    svc     #0

    .bss
    .balign 8
ev:
    .skip   16
obuf:
    .skip   64                      // 4 * sizeof(epoll_event)
wbuf:
    .skip   8
rbuf:
    .skip   8
