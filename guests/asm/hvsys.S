// Instructions Linux lets EL0 execute that a VM traps to the hypervisor:
// `wfi` returns, and the physical counter reads and advances. Exit 0.
    .text
    .globl _start
_start:
    wfi
    mrs     x19, cntpct_el0
    mov     x8, #172                // getpid: a little time passes
    svc     #0
    mrs     x20, cntpct_el0
    cmp     x20, x19
    b.ls    fail
    // The physical and virtual counters agree to within a second (24 MHz).
    mrs     x21, cntvct_el0
    subs    x22, x21, x20
    cneg    x22, x22, mi
    movz    x23, #0x16e3, lsl #16   // 24,000,000 > 0x16e30000? close enough
    cmp     x22, x23
    b.hs    fail
    mov     x0, #0
    b       exit
fail:
    mov     x0, #1
exit:
    mov     x8, #94
    svc     #0
