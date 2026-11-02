// Open /proc/sys/kernel/ostype and verify it reads "Linux". Exit 0 on match.
    .text
    .globl _start
_start:
    movn    x0, #99                 // AT_FDCWD
    adr     x1, path
    mov     w2, #0                  // O_RDONLY
    mov     w3, #0
    mov     x8, #56                 // openat
    svc     #0
    tbnz    x0, #63, fail
    mov     x19, x0                 // fd

    mov     x0, x19
    adr     x1, buf
    mov     x2, #16
    mov     x8, #63                 // read
    svc     #0
    cmp     x0, #5
    b.lt    fail

    adr     x9, buf
    adr     x10, expect
    mov     x11, #5
cmp_loop:
    ldrb    w12, [x9], #1
    ldrb    w13, [x10], #1
    cmp     w12, w13
    b.ne    fail
    subs    x11, x11, #1
    b.ne    cmp_loop

    mov     x0, #0
    b       exit
fail:
    mov     x0, #1
exit:
    mov     x8, #94                 // exit_group
    svc     #0

    .section .rodata
path:
    .asciz  "/proc/sys/kernel/ostype"
expect:
    .ascii  "Linux"

    .bss
    .balign 8
buf:
    .skip   64
