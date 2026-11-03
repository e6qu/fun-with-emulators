// FP/SIMD state across a signal handler: the handler finds the interrupted
// v-registers and FPCR in the frame's fpsimd_context record, clobbers the
// live ones, and they are back when it returns. Exit 0 on success, 1 if the
// state was lost, 2 if the frame's record was wrong.
    .text
    .globl _start
_start:
    // act.sa_handler = handler (stored at run time: no relocations in PIE)
    adr     x9, act
    adr     x10, handler
    str     x10, [x9]
    // rt_sigaction(SIGUSR1, &act, NULL, 8)
    mov     x0, #10
    adr     x1, act
    mov     x2, #0
    mov     x3, #8
    mov     x8, #134
    svc     #0
    cbnz    x0, fail

    // Live FP state: three vector registers and a rounding mode.
    adr     x9, pattern
    ldr     q0, [x9]
    ldr     q8, [x9, #16]
    ldr     q31, [x9, #32]
    mov     x19, #0x400000          // FPCR.RMode = round towards +infinity
    msr     fpcr, x19

    // kill(getpid(), SIGUSR1): the handler runs as the call returns.
    mov     x8, #172
    svc     #0
    mov     x1, #10
    mov     x8, #129
    svc     #0

    adr     x9, handled
    ldr     w10, [x9]
    cmp     w10, #1
    b.ne    fail

    adr     x9, pattern
    ldr     q1, [x9]
    cmeq    v2.16b, v0.16b, v1.16b
    uminv   b3, v2.16b
    umov    w4, v3.b[0]
    cmp     w4, #0xff
    b.ne    fail
    ldr     q1, [x9, #16]
    cmeq    v2.16b, v8.16b, v1.16b
    uminv   b3, v2.16b
    umov    w4, v3.b[0]
    cmp     w4, #0xff
    b.ne    fail
    ldr     q1, [x9, #32]
    cmeq    v2.16b, v31.16b, v1.16b
    uminv   b3, v2.16b
    umov    w4, v3.b[0]
    cmp     w4, #0xff
    b.ne    fail
    mrs     x11, fpcr
    cmp     x11, x19
    b.ne    fail

    mov     x0, #0
    b       exit
fail:
    mov     x0, #1
exit:
    mov     x8, #94                 // exit_group
    svc     #0

// handler(sig, info, ucontext)
handler:
    // __reserved is at ucontext + 176 (uc_mcontext) + 288.
    add     x9, x2, #464
    ldr     w10, [x9]               // magic
    movz    w11, #0x8001
    movk    w11, #0x4650, lsl #16
    cmp     w10, w11
    b.ne    hfail
    ldr     w10, [x9, #4]           // size
    cmp     w10, #528
    b.ne    hfail
    ldr     w10, [x9, #12]          // fpcr
    cmp     w10, #0x400000
    b.ne    hfail
    ldr     q4, [x9, #16]           // vregs[0]
    adr     x12, pattern
    ldr     q5, [x12]
    cmeq    v6.16b, v4.16b, v5.16b
    uminv   b7, v6.16b
    umov    w13, v7.b[0]
    cmp     w13, #0xff
    b.ne    hfail

    // Clobber the live state.
    movi    v0.16b, #0
    movi    v8.16b, #0
    movi    v31.16b, #0
    msr     fpcr, xzr

    adr     x9, handled
    mov     w10, #1
    str     w10, [x9]
    ret
hfail:
    mov     x0, #2
    mov     x8, #94
    svc     #0

    .data
    .balign 16
pattern:
    .quad   0x0123456789abcdef, 0xfedcba9876543210
    .quad   0x1111222233334444, 0x5555666677778888
    .quad   0x9999aaaabbbbcccc, 0xddddeeeeffff0000
act:
    .quad   0                       // sa_handler, set at run time
    .quad   4                       // sa_flags: SA_SIGINFO
    .quad   0                       // sa_restorer
    .quad   0                       // sa_mask
handled:
    .word   0
