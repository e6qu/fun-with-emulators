// Uses of x18 while sp is not 16-byte aligned, as in pixman's NEON
// functions (`sub sp, sp, #0xe8` under a frame, then `stp x18, x19,
// [x29, #-0xa0]`): Linux lets a program keep such an sp while it stores
// through other registers. A store and a load of x18 through x29, sp
// read and written through x18, instruction-cache flushes through x18
// and another register, a thread-pointer write, and a store of x18
// through a null pointer, whose
// SIGSEGV handler sees the fault at the store itself with every
// register and sp as they were, then skips it. A timer's SIGALRM lands
// throughout. Exit 0 on success, otherwise 1 + the number of the register
// found wrong (40 for pc, 41 for sp, 42 if the handler did not run, 43 for
// the thread pointer).
    .text
    .globl _start
_start:
    sub     sp, sp, #32             // struct sigaction on the stack
    adr     x9, segv
    str     x9, [sp, #0]            // sa_handler
    mov     x9, #4                  // SA_SIGINFO
    str     x9, [sp, #8]            // sa_flags
    str     xzr, [sp, #16]          // sa_restorer = 0
    str     xzr, [sp, #24]          // sa_mask = 0
    mov     x0, #11                 // SIGSEGV
    mov     x1, sp
    mov     x2, #0
    mov     x3, #8
    mov     x8, #134                // rt_sigaction
    svc     #0
    adr     x9, alarm
    str     x9, [sp, #0]
    mov     x9, #0x10000000         // SA_RESTART
    str     x9, [sp, #8]
    mov     x0, #14                 // SIGALRM
    mov     x1, sp
    mov     x2, #0
    mov     x3, #8
    mov     x8, #134
    svc     #0
    add     sp, sp, #32
    // Every 100 us: struct itimerval { interval, value }.
    sub     sp, sp, #32
    mov     x9, #0
    mov     x10, #100
    stp     x9, x10, [sp, #0]
    stp     x9, x10, [sp, #16]
    mov     x0, #0                  // ITIMER_REAL
    mov     x1, sp
    mov     x2, #0
    mov     x8, #103                // setitimer
    svc     #0
    add     sp, sp, #32

    mov     x28, #5000              // rounds
round:
    stp     x29, x30, [sp, #-16]!
    mov     x29, sp
    sub     sp, sp, #0x48           // sp 8 bytes off alignment
    adr     x8, sp_seen
    mov     x30, sp
    str     x30, [x8]
    .irp n, 0,1,2,3,4,5,6,7,9,10,11,12,13,14,15,16,17,19,20,21,22,23,24,25,26,27
    movz    x\n, #(0x1000 + \n)
    movk    x\n, #0x5a5a, lsl #32
    .endr
    movz    x18, #0x1818
    movk    x18, #0x5a5a, lsl #32

    stp     x18, x19, [x29, #-32]
    mov     x18, sp                 // sp read and written through x18
    mov     sp, x18
    adr     x18, round              // code flushed through x18 and x8
    ic      ivau, x18
    adr     x8, round
    ic      ivau, x8
    dsb     ish
    isb
    movz    x18, #0
    ldp     x18, x19, [x29, #-32]
    msr     tpidr_el0, x29
    movz    x20, #0                 // null
site:
    str     x18, [x20]              // faults; the handler skips it
    movz    x20, #(0x1000 + 20)
    movk    x20, #0x5a5a, lsl #32
    // Every register as before.
    .irp n, 0,1,2,3,4,5,6,7,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27
    movz    x8, #(0x1000 + \n)
    .if \n == 18
    movz    x8, #0x1818
    .endif
    movk    x8, #0x5a5a, lsl #32
    cmp     x\n, x8
    b.ne    lost_\n
    .endr
    mrs     x8, tpidr_el0
    cmp     x8, x29
    b.ne    lost_tp
    adr     x8, ran
    ldr     w9, [x8]
    cbz     w9, no_handler
    str     wzr, [x8]
    mov     sp, x29
    ldp     x29, x30, [sp], #16
    subs    x28, x28, #1
    b.ne    round
    mov     x0, #0
    b       exit

segv:
    // x2 = ucontext: regs[n] at 184 + 8n, sp at 432, pc at 440.
    .irp n, 0,1,3,4,5,6,7,9,10,11,12,13,14,15,16,17,19,21,22,23,24,25,26,27
    ldr     x9, [x2, #(184 + 8 * \n)]
    movz    x10, #(0x1000 + \n)
    movk    x10, #0x5a5a, lsl #32
    cmp     x9, x10
    b.ne    seen_\n
    .endr
    ldr     x9, [x2, #(184 + 8 * 18)]
    movz    x10, #0x1818
    movk    x10, #0x5a5a, lsl #32
    cmp     x9, x10
    b.ne    seen_18
    ldr     x9, [x2, #(184 + 8 * 20)]
    cbnz    x9, seen_20
    ldr     x9, [x2, #440]          // pc: the store itself
    adr     x10, site
    cmp     x9, x10
    b.ne    seen_pc
    ldr     x9, [x2, #432]          // sp: as the program had it
    adr     x10, sp_seen
    ldr     x10, [x10]
    cmp     x9, x10
    b.ne    seen_sp
    adr     x10, site               // skip the store
    add     x10, x10, #4
    str     x10, [x2, #440]
    adr     x9, ran
    mov     w10, #1
    str     w10, [x9]
    ret

alarm:
    ret

    // x2 holds the ucontext in the handler, so its value is not checked
    // there (it is after the return).
    .irp n, 0,1,3,4,5,6,7,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27
seen_\n:
    mov     x0, #(1 + \n)
    b       exit
    .endr
seen_pc:
    mov     x0, #40
    b       exit
seen_sp:
    mov     x0, #41
    b       exit

    .irp n, 0,1,2,3,4,5,6,7,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27
lost_\n:
    mov     x0, #(1 + \n)
    b       exit
    .endr
lost_tp:
    mov     x0, #43
    b       exit
no_handler:
    mov     x0, #42
exit:
    mov     x8, #94                 // exit_group
    svc     #0

    .data
    .balign 8
sp_seen:
    .quad   0
ran:
    .word   0
