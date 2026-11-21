// A program whose image is larger than a branch reaches across: a
// function in its middle, 132 MiB of code before it and 140 MiB of data
// after it, uses x18 and reads the thread pointer. No place outside the
// image is within a branch of it. The program sets the thread pointer,
// calls the function 1000 times (through a register: a call reaches only
// 128 MiB) and checks what it returns; it prints "big image: ok" and
// exits 0, or exits 1.
    .text
    .globl _start
_start:
    adrp    x19, tls
    add     x19, x19, :lo12:tls
    msr     tpidr_el0, x19
    adrp    x20, middle
    add     x20, x20, :lo12:middle
    mov     x21, #1000
1:  blr     x20
    cmp     x0, #43
    b.ne    fail
    cmp     x1, x19
    b.ne    fail
    subs    x21, x21, #1
    b.ne    1b
    mov     x0, #1
    adrp    x1, msg
    add     x1, x1, :lo12:msg
    mov     x2, #14
    mov     x8, #64             // write
    svc     #0
    mov     x0, #0
    mov     x8, #93             // exit
    svc     #0
fail:
    mov     x0, #1
    mov     x8, #93
    svc     #0

    .space  132 * 1024 * 1024
    .globl middle
    .type middle, %function
middle:
    mov     x18, #42
    add     x0, x18, #1
    mrs     x1, tpidr_el0
    ret

    .section .rodata
msg:
    .ascii  "big image: ok\n"

    .bss
    .balign 16
tls:
    .space  16
    .space  140 * 1024 * 1024
