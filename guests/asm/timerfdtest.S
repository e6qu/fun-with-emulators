// timerfd: arm a one-shot timer 40ms out, block in read, and expect at least
// one expiration. Exit 0 on success, 1 on failure.
    .text
    .globl _start
_start:
    // tfd = timerfd_create(CLOCK_MONOTONIC(1), 0)
    mov     w0, #1
    mov     w1, #0
    mov     x8, #85                 // timerfd_create
    svc     #0
    tbnz    x0, #63, fail
    mov     x19, x0                 // tfd

    // itimerspec { it_interval = {0,0}; it_value = {0, 40_000_000} }
    adr     x9, spec
    mov     x10, #0
    str     x10, [x9]               // it_interval.tv_sec
    str     x10, [x9, #8]           // it_interval.tv_nsec
    str     x10, [x9, #16]          // it_value.tv_sec
    movz    x11, #0x5A00            // 40_000_000 = 0x02625A00
    movk    x11, #0x0262, lsl #16
    str     x11, [x9, #24]          // it_value.tv_nsec = 40ms

    // timerfd_settime(tfd, 0, &spec, NULL)
    mov     x0, x19
    mov     w1, #0
    adr     x2, spec
    mov     x3, #0
    mov     x8, #86                 // timerfd_settime
    svc     #0
    tbnz    x0, #63, fail

    // read(tfd, buf, 8) -> 8, expirations >= 1
    mov     x0, x19
    adr     x1, buf
    mov     x2, #8
    mov     x8, #63                 // read
    svc     #0
    cmp     x0, #8
    b.ne    fail
    adr     x9, buf
    ldr     x10, [x9]
    cmp     x10, #1
    b.lt    fail

    mov     x0, #0
    b       exit
fail:
    mov     x0, #1
exit:
    mov     x8, #94                 // exit_group
    svc     #0

    .bss
    .balign 8
spec:
    .skip   32
buf:
    .skip   8
