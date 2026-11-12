// sp written from x18 while signals arrive. `mov sp, x18` moves sp up past
// where its stub saved two scratch registers, then reads them back; a
// signal frame written in between would overwrite them, so the signal's
// delivery finishes those reads first. A fast interval timer interrupts the
// loop many times; the registers the stub borrows (x0, x1) must keep their
// values throughout. Exit 0 if they do, 1 otherwise.
    .text
    .globl _start
_start:
    sub     sp, sp, #32             // struct sigaction on the stack
    adr     x9, handler
    str     x9, [sp, #0]            // sa_handler
    movz    x9, #0x1000, lsl #16    // SA_RESTART
    orr     x9, x9, #4              // | SA_SIGINFO
    str     x9, [sp, #8]            // sa_flags
    str     xzr, [sp, #16]          // sa_restorer = 0
    str     xzr, [sp, #24]          // sa_mask = 0
    mov     x0, #14                 // SIGALRM
    mov     x1, sp
    mov     x2, #0
    mov     x3, #8
    mov     x8, #134                // rt_sigaction
    svc     #0
    add     sp, sp, #32
    tbnz    x0, #63, fail

    // setitimer(ITIMER_REAL, {50 us, 50 us}, NULL)
    sub     sp, sp, #32
    mov     x9, #50
    stp     xzr, x9, [sp]           // it_interval
    stp     xzr, x9, [sp, #16]      // it_value
    mov     x0, #0
    mov     x1, sp
    mov     x2, #0
    mov     x8, #103                // setitimer
    svc     #0
    add     sp, sp, #32
    tbnz    x0, #63, fail

    mov     x20, sp                 // the top the loop returns sp to
    movz    x19, #0x0200, lsl #16   // iterations
loop:
    movz    x0, #0xa0a0
    movz    x1, #0xb1b1
    mov     x18, x20
    sub     sp, sp, #64
    mov     sp, x18                 // up past the stub's saved registers
    movz    x2, #0xa0a0
    cmp     x0, x2
    b.ne    fail
    movz    x2, #0xb1b1
    cmp     x1, x2
    b.ne    fail
    mov     x3, sp
    cmp     x3, x20
    b.ne    fail
    subs    x19, x19, #1
    b.ne    loop

    // Stop the timer.
    sub     sp, sp, #32
    stp     xzr, xzr, [sp]
    stp     xzr, xzr, [sp, #16]
    mov     x0, #0
    mov     x1, sp
    mov     x2, #0
    mov     x8, #103
    svc     #0
    add     sp, sp, #32
    mov     x0, #0
    b       exit
fail:
    mov     x0, #1
exit:
    mov     x8, #94                 // exit_group
    svc     #0

handler:
    ret                             // -> rt_sigreturn trampoline
