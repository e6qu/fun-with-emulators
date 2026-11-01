// An unknown system call must fail with -ENOSYS (-38); exit 0 if it does.
    .text
    .globl _start
_start:
    mov     x8, #4000
    svc     #0
    cmn     x0, #38
    cset    x0, ne
    mov     x8, #94                 // exit_group
    svc     #0
