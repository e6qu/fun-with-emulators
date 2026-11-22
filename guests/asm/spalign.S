// An sp kept off 16-byte alignment, as Linux lets a program keep it while
// it addresses memory through other registers. The program's own store
// through it faults as on Linux: SIGBUS, BUS_ADRALN, at sp, the handler
// seeing the store and sp as they were (it skips the store). Code made at
// run time, which calls through a register, returns and uses x18, runs
// with that sp 2000 times and gives its result. Exit 0 on success; 1 no
// SIGBUS; 2 its code; 3 its address; 4 its pc; 5 its sp; 6 the code's
// result; 7 mmap failed.
    .text
    .globl _start
_start:
    sub     sp, sp, #32             // struct sigaction on the stack
    adr     x9, bus
    str     x9, [sp, #0]            // sa_handler
    mov     x9, #4                  // SA_SIGINFO
    str     x9, [sp, #8]            // sa_flags
    str     xzr, [sp, #16]          // sa_restorer = 0
    str     xzr, [sp, #24]          // sa_mask = 0
    mov     x0, #7                  // SIGBUS
    mov     x1, sp
    mov     x2, #0
    mov     x3, #8
    mov     x8, #134                // rt_sigaction
    svc     #0
    add     sp, sp, #32

    // The code, copied into memory mapped writable and executable.
    mov     x0, #0
    mov     x1, #4096
    mov     x2, #7                  // PROT_READ | PROT_WRITE | PROT_EXEC
    mov     x3, #0x22               // MAP_PRIVATE | MAP_ANONYMOUS
    mov     x4, #-1
    mov     x5, #0
    mov     x8, #222                // mmap
    svc     #0
    cmn     x0, #4096
    b.hi    no_map
    mov     x20, x0
    adr     x9, made
    adr     x10, made_end
    mov     x11, x20
1:  ldr     w12, [x9], #4
    str     w12, [x11], #4
    cmp     x9, x10
    b.lo    1b
    mov     x13, x11                // the copy's end
    mov     x11, x20
2:  dc      cvau, x11
    ic      ivau, x11
    add     x11, x11, #4
    cmp     x11, x13
    b.lo    2b
    dsb     ish
    isb

    sub     sp, sp, #8              // sp 8 bytes off alignment
    adr     x8, sp_seen
    mov     x9, sp
    str     x9, [x8]
own:
    str     x0, [sp]                // faults; the handler skips it
    adr     x8, ran
    ldr     w9, [x8]
    cbz     w9, no_bus

    mov     x21, #2000
    mov     x0, #0
3:  blr     x20
    subs    x21, x21, #1
    b.ne    3b
    mov     x9, #6000               // three a call
    cmp     x0, x9
    b.ne    bad_result
    add     sp, sp, #8
    mov     x0, #0
    b       exit

bus:
    // x1 = siginfo: si_code at 8, si_addr at 16; x2 = ucontext: sp at
    // 432, pc at 440.
    ldr     w9, [x1, #8]
    cmp     w9, #1                  // BUS_ADRALN
    b.ne    bad_code
    adr     x10, sp_seen
    ldr     x10, [x10]
    ldr     x9, [x1, #16]
    cmp     x9, x10
    b.ne    bad_addr
    ldr     x9, [x2, #432]
    cmp     x9, x10
    b.ne    bad_sp
    ldr     x9, [x2, #440]
    adr     x10, own
    cmp     x9, x10
    b.ne    bad_pc
    add     x9, x9, #4
    str     x9, [x2, #440]
    adr     x9, ran
    mov     w10, #1
    str     w10, [x9]
    ret


no_bus:
    mov     x0, #1
    b       exit
bad_code:
    mov     x0, #2
    b       exit
bad_addr:
    mov     x0, #3
    b       exit
bad_pc:
    mov     x0, #4
    b       exit
bad_sp:
    mov     x0, #5
    b       exit
bad_result:
    mov     x0, #6
    b       exit
no_map:
    mov     x0, #7
exit:
    mov     x8, #94                 // exit_group
    svc     #0

    .data
    // Copied out and run from there: adds 3 to x0, by calls through a
    // register and through x18, and through x18 itself. Kept as data, as a JIT keeps the code it
    // copies (fwe rewrites x18's uses in the program's own code).
    .balign 4
made:
    mov     x9, x30
    adr     x10, add_one
    blr     x10
    mov     x18, x0
    add     x18, x18, #1
    mov     x0, x18
    mov     x18, x10
    blr     x18
    mov     x30, x9
    ret
add_one:
    add     x0, x0, #1
    ret
made_end:
    .balign 8
sp_seen:
    .quad   0
ran:
    .word   0
