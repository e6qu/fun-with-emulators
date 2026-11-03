// Two edge cases a backend must get right. Exit 0 on success.
// 1 (exit 1/2): a signal blocked while a handler runs, and raised by it, is
//   delivered as soon as the handler returns, although the program then
//   spins without system calls.
// 2 (exit 3/4): mmap with MAP_FIXED over a page of the program's own .bss
//   returns that address and gives a fresh zeroed page.
    .text
    .globl _start
_start:
    adr     x9, act_usr1
    adr     x10, on_usr1
    str     x10, [x9]
    adr     x9, act_rt
    adr     x10, on_rt
    str     x10, [x9]
    mov     x0, #10                 // rt_sigaction(SIGUSR1, &act_usr1, 0, 8)
    adr     x1, act_usr1
    mov     x2, #0
    mov     x3, #8
    mov     x8, #134
    svc     #0
    cbnz    x0, fail1
    mov     x0, #40                 // rt_sigaction(40, &act_rt, 0, 8)
    adr     x1, act_rt
    mov     x2, #0
    mov     x3, #8
    mov     x8, #134
    svc     #0
    cbnz    x0, fail1
    mov     x8, #172                // kill(getpid(), SIGUSR1)
    svc     #0
    mov     x1, #10
    mov     x8, #129
    svc     #0
    // No system calls from here until the flag is checked.
    adr     x9, rt_hit
    movz    x11, #0x4000, lsl #16
spin:
    ldr     w10, [x9]
    cbnz    w10, part2
    subs    x11, x11, #1
    b.ne    spin
    mov     x0, #2
    b       exit

part2:
    adr     x19, page               // 16 KiB-aligned page in .bss
    mov     w10, #0x5a
    strb    w10, [x19]
    mov     x0, x19                 // mmap(page, 16384, RW, PRIVATE|ANON|FIXED, -1, 0)
    mov     x1, #16384
    mov     x2, #3
    mov     x3, #0x32
    mov     x4, #-1
    mov     x5, #0
    mov     x8, #222
    svc     #0
    cmp     x0, x19
    b.ne    fail3
    ldrb    w10, [x19]              // fresh: zero
    cbnz    w10, fail4
    mov     w10, #1
    strb    w10, [x19]
    mov     x0, #0
    b       exit
fail1:
    mov     x0, #1
    b       exit
fail3:
    mov     x0, #3
    b       exit
fail4:
    mov     x0, #4
exit:
    mov     x8, #94
    svc     #0

// SIGUSR1 handler: raise signal 40, which this handler's mask blocks.
on_usr1:
    mov     x8, #172                // getpid
    svc     #0
    mov     x1, #40
    mov     x8, #129                // kill(getpid(), 40)
    svc     #0
    ret

on_rt:
    adr     x9, rt_hit
    mov     w10, #1
    str     w10, [x9]
    ret

    .data
    .balign 8
act_usr1:
    .quad   0                       // handler, set at run time
    .quad   0                       // flags
    .quad   0                       // restorer
    .quad   1 << 39                 // mask: signal 40
act_rt:
    .quad   0
    .quad   0
    .quad   0
    .quad   0
rt_hit:
    .word   0

    .bss
    .balign 16384
page:
    .space  16384
