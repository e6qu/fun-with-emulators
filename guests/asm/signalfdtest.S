// signalfd: block SIGUSR1, create a signalfd for it, raise it, and read the
// queued siginfo back, checking ssi_signo. Exit 0 on success.
    .text
    .globl _start
_start:
    // set = { SIGUSR1 } : bit (10-1) = 0x200
    adr     x9, mask
    mov     x10, #0x200
    str     x10, [x9]

    // rt_sigprocmask(SIG_BLOCK=0, &set, NULL, 8)
    mov     x0, #0
    adr     x1, mask
    mov     x2, #0
    mov     x3, #8
    mov     x8, #135                // rt_sigprocmask
    svc     #0
    tbnz    x0, #63, fail

    // signalfd4(-1, &set, 8, 0)
    mov     x0, #-1
    adr     x1, mask
    mov     x2, #8
    mov     x3, #0
    mov     x8, #74                 // signalfd4
    svc     #0
    tbnz    x0, #63, fail
    mov     x19, x0                 // sfd

    // kill(getpid(), SIGUSR1)
    mov     x8, #172                // getpid
    svc     #0
    mov     x1, #10
    mov     x8, #129                // kill
    svc     #0
    tbnz    x0, #63, fail

    // read(sfd, buf, 128)
    mov     x0, x19
    adr     x1, buf
    mov     x2, #128
    mov     x8, #63                 // read
    svc     #0
    cmp     x0, #128
    b.ne    fail

    // ssi_signo (first u32) == SIGUSR1 (10)
    adr     x9, buf
    ldr     w10, [x9]
    cmp     w10, #10
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
mask:
    .skip   8
buf:
    .skip   128
