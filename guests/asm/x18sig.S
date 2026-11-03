// x18 across a signal handler. The handler, entered with SA_SIGINFO, checks
// that uc_mcontext.regs[18] holds the guest's x18 and uc_mcontext.pc the
// resume address (at the arm64 frame offsets), sets a flag, and clobbers x18;
// rt_sigreturn must restore it. Exit 0 on success, 1 otherwise.
    .text
    .globl _start
_start:
    sub     sp, sp, #32             // struct sigaction on the stack
    adr     x9, handler
    str     x9, [sp, #0]            // sa_handler
    mov     x9, #4                  // SA_SIGINFO
    str     x9, [sp, #8]            // sa_flags
    str     xzr, [sp, #16]          // sa_restorer = 0
    str     xzr, [sp, #24]          // sa_mask = 0
    mov     x0, #10                 // SIGUSR1
    mov     x1, sp                  // act
    mov     x2, #0                  // oldact
    mov     x3, #8                  // sigsetsize
    mov     x8, #134                // rt_sigaction
    svc     #0
    add     sp, sp, #32
    tbnz    x0, #63, fail

    movz    x18, #0x1818
    movk    x18, #0x1818, lsl #48
    mov     x10, x18                // the value the handler must see
    mov     x8, #172                // getpid
    svc     #0
    mov     x1, #10                 // SIGUSR1
    mov     x8, #129                // kill(pid, SIGUSR1)
    adr     x12, resumed            // the pc the handler must see
    svc     #0
resumed:
    tbnz    x0, #63, fail
    cmp     x18, x10                // restored after the handler clobbered it
    b.ne    fail
    adr     x9, flag
    ldr     w11, [x9]
    cmp     w11, #1
    b.ne    fail
    mov     x0, #0
    b       exit
fail:
    mov     x0, #1
exit:
    mov     x8, #94                 // exit_group
    svc     #0

handler:
    // x2 = ucontext: uc_mcontext at 176, regs[] at +8, pc at +264.
    ldr     x11, [x2, #328]         // regs[18]
    cmp     x11, x10
    b.ne    1f
    ldr     x11, [x2, #440]         // pc
    cmp     x11, x12
    b.ne    1f
    adr     x9, flag
    mov     w11, #1
    str     w11, [x9]
1:
    mov     x18, #0                 // clobber; sigreturn restores it
    ret                             // -> rt_sigreturn trampoline

    .data
    .balign 4
flag:
    .word   0
