// Install a SIGUSR1 handler (no sa_restorer), raise SIGUSR1, and confirm the
// handler ran by checking a flag it sets. The handler returns through fwe's
// rt_sigreturn trampoline. Exit 0 on success, 1 otherwise.
    .text
    .globl _start
_start:
    sub     sp, sp, #32             // struct sigaction on the stack
    adr     x9, handler
    str     x9, [sp, #0]            // sa_handler
    str     xzr, [sp, #8]           // sa_flags = 0
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

    mov     x8, #172                // getpid
    svc     #0
    mov     x19, x0                 // pid
    mov     x0, x19
    mov     x1, #10                 // SIGUSR1
    mov     x8, #129                // kill(pid, SIGUSR1)
    svc     #0
    tbnz    x0, #63, fail

    adr     x10, flag               // handler should have set this
    ldr     w11, [x10]
    cmp     w11, #0x7a
    b.ne    fail
    mov     x0, #0
    b       exit
fail:
    mov     x0, #1
exit:
    mov     x8, #94                 // exit_group
    svc     #0

handler:
    adr     x10, flag
    mov     w11, #0x7a
    str     w11, [x10]
    ret                             // -> rt_sigreturn trampoline

    .data
    .balign 4
flag:
    .word   0
