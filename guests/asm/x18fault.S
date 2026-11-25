// A load through x18 that faults, as a JIT's implicit null check does
// (HotSpot loads through a register that might be null and turns the
// SIGSEGV into a NullPointerException). The handler sees the fault at
// the load itself, every register as it was and sp unchanged, then skips
// the load; afterwards every register is still as it was. Exit 0 on
// success, otherwise 1 + the number of the register found wrong (40 for
// pc, 41 for sp, 42 if the handler did not run).
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
    mov     x0, #11                 // SIGSEGV
    mov     x1, sp
    mov     x2, #0
    mov     x3, #8
    mov     x8, #134                // rt_sigaction
    svc     #0
    add     sp, sp, #32

    mov     x28, #200               // rounds
round:
    adr     x8, sp_seen
    mov     x30, sp
    str     x30, [x8]
    .irp n, 0,1,2,3,4,5,6,7,9,10,11,12,13,14,15,16,17,19,20,21,22,23,24,25,26,27,29
    movz    x\n, #(0x1000 + \n)
    movk    x\n, #0x5a5a, lsl #32
    .endr
    movz    x18, #0                 // null
site:
    ldr     x30, [x18, #16]         // faults; the handler skips it
    // Every register as before the fault.
    .irp n, 0,1,2,3,4,5,6,7,9,10,11,12,13,14,15,16,17,19,20,21,22,23,24,25,26,27,29
    movz    x8, #(0x1000 + \n)
    movk    x8, #0x5a5a, lsl #32
    cmp     x\n, x8
    b.ne    lost_\n
    .endr
    cbnz    x18, lost_18
    adr     x8, ran
    ldr     w9, [x8]
    cbz     w9, no_handler
    str     wzr, [x8]
    subs    x28, x28, #1
    b.ne    round
    mov     x0, #0
    b       exit

handler:
    // x2 = ucontext: regs[n] at 184 + 8n, sp at 432, pc at 440.
    .irp n, 0,1,3,4,5,6,7,9,10,11,12,13,14,15,16,17,19,20,21,22,23,24,25,26,27,29
    ldr     x9, [x2, #(184 + 8 * \n)]
    movz    x10, #(0x1000 + \n)
    movk    x10, #0x5a5a, lsl #32
    cmp     x9, x10
    b.ne    seen_\n
    .endr
    ldr     x9, [x2, #(184 + 8 * 18)]
    cbnz    x9, seen_18
    ldr     x9, [x2, #440]          // pc: the load itself
    adr     x10, site
    cmp     x9, x10
    b.ne    seen_pc
    ldr     x9, [x2, #432]          // sp: as the program had it
    adr     x10, sp_seen
    ldr     x10, [x10]
    cmp     x9, x10
    b.ne    seen_sp
    add     x9, x10, #0             // keep x9 busy; skip the load:
    adr     x10, site
    add     x10, x10, #4
    str     x10, [x2, #440]
    adr     x9, ran
    mov     w10, #1
    str     w10, [x9]
    ret

    // x2 holds the ucontext in the handler, so its value is not checked
    // there (it is after the return).
    .irp n, 0,1,3,4,5,6,7,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,29
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

    .irp n, 0,1,2,3,4,5,6,7,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,29
lost_\n:
    mov     x0, #(1 + \n)
    b       exit
    .endr
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
