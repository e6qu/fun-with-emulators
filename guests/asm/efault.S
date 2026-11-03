// Bad guest pointers make system calls fail with EFAULT (-14) rather than
// crash: both the pointers the kernel layer reads or writes itself and those
// it hands to the host. Each check exits with its own status on failure;
// exit 0 means every call returned EFAULT.
    .text
    .globl _start

// check N: the result in x0 must be -14, else exit N.
.macro check n
    cmn     x0, #14
    b.eq    1f
    mov     x0, #\n
    b       exit
1:
.endm

_start:
    mov     x20, #0x10              // never mapped: inside the low 4 GiB
    adr     x21, _start             // mapped, but read-only code

    mov     x0, x20                 // uname(bad)
    mov     x8, #160
    svc     #0
    check   1

    mov     x0, x21                 // uname(read-only)
    mov     x8, #160
    svc     #0
    check   2

    mov     x0, #-100               // openat(AT_FDCWD, bad, 0)
    mov     x1, x20
    mov     x2, #0
    mov     x8, #56
    svc     #0
    check   3

    mov     x0, #10                 // rt_sigaction(SIGUSR1, bad, NULL, 8)
    mov     x1, x20
    mov     x2, #0
    mov     x3, #8
    mov     x8, #134
    svc     #0
    check   4

    mov     x0, #0                  // getrandom(bad, 16, 0)
    mov     x0, x20
    mov     x1, #16
    mov     x2, #0
    mov     x8, #278
    svc     #0
    check   5

    mov     x0, x20                 // pipe2(bad, 0)
    mov     x1, #0
    mov     x8, #59
    svc     #0
    check   6

    mov     x0, x20                 // getcwd(bad, 256)
    mov     x1, #256
    mov     x8, #17
    svc     #0
    check   7

    mov     x0, x20                 // execve(bad, NULL, NULL)
    mov     x1, #0
    mov     x2, #0
    mov     x8, #221
    svc     #0
    check   8

    mov     x0, x20                 // sigaltstack(bad, NULL)
    mov     x1, #0
    mov     x8, #132
    svc     #0
    check   9

    mov     x0, #0                  // clock_gettime(CLOCK_REALTIME, bad): the host checks
    mov     x1, x20
    mov     x8, #113
    svc     #0
    check   10

    mov     x0, #1                  // write(1, bad, 5): the host checks
    mov     x1, x20
    mov     x2, #5
    mov     x8, #64
    svc     #0
    check   11

    mov     x0, #-100               // newfstatat(AT_FDCWD, "/", bad, 0)
    adr     x1, root
    mov     x2, x20
    mov     x3, #0
    mov     x8, #79
    svc     #0
    check   12

    mov     x0, #0
exit:
    mov     x8, #94                 // exit_group
    svc     #0

root:
    .asciz  "/"
