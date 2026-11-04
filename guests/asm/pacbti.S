// Pointer authentication and BTI as Linux gives them to a program, where
// the machine offers them (AT_HWCAP's PACA, AT_HWCAP2's BTI): a pointer
// signed and authenticated round-trips; a fork child has its parent's keys;
// PR_PAC_RESET_KEYS changes them; an indirect branch to a landing pad goes
// on, one to anything else raises SIGILL, whose handler is entered as from
// `blr` (so it begins with `bti c`). The program is built for BTI (see the
// note at the end), so the loader maps its code guarded. Prints a line per
// check; exits 0, or 1 on a failed check.
    .arch   armv8.5-a
    .text
    .globl _start
_start:
    // The auxiliary vector, past argv and envp.
    ldr     x0, [sp]
    add     x1, sp, #8
    add     x1, x1, x0, lsl #3
    add     x1, x1, #8
1:  ldr     x2, [x1], #8
    cbnz    x2, 1b
    mov     x19, #0                 // AT_HWCAP
    mov     x20, #0                 // AT_HWCAP2
2:  ldp     x2, x3, [x1], #16
    cbz     x2, 3f
    cmp     x2, #16
    csel    x19, x3, x19, eq
    cmp     x2, #26
    csel    x20, x3, x20, eq
    b       2b
3:
    tbz     x19, #30, no_pac        // HWCAP_PACA

    // Sign and authenticate a pointer.
    adr     x21, _start
    mov     x22, #0x1234            // the modifier
    mov     x0, x21
    pacia   x0, x22
    cmp     x0, x21
    b.eq    fail                    // signing left it as it was
    mov     x23, x0                 // the signed pointer
    autia   x0, x22
    cmp     x0, x21
    b.ne    fail
    adr     x1, m_roundtrip
    mov     x2, #(m_roundtrip_end - m_roundtrip)
    bl      print

    // A fork child signs it the same: it has the parent's keys.
    mov     x0, #17                 // SIGCHLD
    mov     x1, #0
    mov     x2, #0
    mov     x3, #0
    mov     x4, #0
    mov     x8, #220                // clone
    svc     #0
    tbnz    x0, #63, fail
    cbnz    x0, 4f
    mov     x0, x21
    pacia   x0, x22
    cmp     x0, x23
    cset    w0, ne
    mov     x8, #94                 // exit_group
    svc     #0
4:  mov     x24, x0                 // the child
    sub     sp, sp, #16
    mov     x0, x24
    mov     x1, sp
    mov     x2, #0
    mov     x3, #0
    mov     x8, #260                // wait4
    svc     #0
    ldr     w0, [sp]
    add     sp, sp, #16
    cbnz    w0, fail                // exited 0, the signature matched
    adr     x1, m_fork
    mov     x2, #(m_fork_end - m_fork)
    bl      print

    // New keys sign differently.
    mov     x0, #54                 // PR_PAC_RESET_KEYS
    mov     x1, #1                  // PR_PAC_APIAKEY
    mov     x2, #0
    mov     x3, #0
    mov     x4, #0
    mov     x8, #167                // prctl
    svc     #0
    cbnz    x0, fail
    mov     x0, x21
    pacia   x0, x22
    cmp     x0, x23
    b.eq    fail
    adr     x1, m_reset
    mov     x2, #(m_reset_end - m_reset)
    bl      print
    b       bti_checks

no_pac:
    adr     x1, m_no_pac
    mov     x2, #(m_no_pac_end - m_no_pac)
    bl      print

bti_checks:
    tbz     x20, #17, no_bti        // HWCAP2_BTI
    // SIGILL's handler.
    sub     sp, sp, #32
    adr     x9, on_sigill
    str     x9, [sp, #0]
    str     xzr, [sp, #8]
    str     xzr, [sp, #16]
    str     xzr, [sp, #24]
    mov     x0, #4                  // SIGILL
    mov     x1, sp
    mov     x2, #0
    mov     x3, #8
    mov     x8, #134                // rt_sigaction
    svc     #0
    add     sp, sp, #32
    tbnz    x0, #63, fail
    // To a landing pad: goes on.
    adr     x9, pad
    br      x9
pad:
    bti     j
    adr     x1, m_pad
    mov     x2, #(m_pad_end - m_pad)
    bl      print
    // To anything else: SIGILL.
    adr     x9, not_a_pad
    br      x9
not_a_pad:
    nop
    adr     x1, m_went_on
    mov     x2, #(m_went_on_end - m_went_on)
    bl      print
    b       fail

on_sigill:
    bti     c
    adr     x1, m_sigill
    mov     x2, #(m_sigill_end - m_sigill)
    bl      print
    mov     x0, #0
    b       exit

no_bti:
    adr     x1, m_no_bti
    mov     x2, #(m_no_bti_end - m_no_bti)
    bl      print
    mov     x0, #0
    b       exit

fail:
    mov     x0, #1
exit:
    mov     x8, #94                 // exit_group
    svc     #0

// write(1, x1, x2)
print:
    mov     x0, #1
    mov     x8, #64
    svc     #0
    ret

    .section .rodata
m_roundtrip:    .ascii "pac: a signed pointer authenticates\n"
m_roundtrip_end:
m_fork:         .ascii "pac: a fork child has its parent's keys\n"
m_fork_end:
m_reset:        .ascii "pac: new keys sign differently\n"
m_reset_end:
m_no_pac:       .ascii "pac: not offered\n"
m_no_pac_end:
m_pad:          .ascii "bti: a branch to a landing pad goes on\n"
m_pad_end:
m_went_on:      .ascii "bti: a branch to no landing pad went on\n"
m_went_on_end:
m_sigill:       .ascii "bti: a branch to no landing pad raises SIGILL\n"
m_sigill_end:
m_no_bti:       .ascii "bti: not offered\n"
m_no_bti_end:

// Built for BTI and PAC: GNU_PROPERTY_AARCH64_FEATURE_1_AND = BTI | PAC.
    .section .note.gnu.property, "a"
    .balign 8
    .word   4
    .word   16
    .word   5                       // NT_GNU_PROPERTY_TYPE_0
    .asciz  "GNU"
    .word   0xc0000000              // GNU_PROPERTY_AARCH64_FEATURE_1_AND
    .word   4
    .word   3
    .word   0
