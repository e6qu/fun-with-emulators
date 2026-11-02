// List /proc via getdents64 and look for the "cpuinfo" entry. Exit 0 if found.
    .text
    .globl _start
_start:
    // openat(AT_FDCWD, "/proc", O_RDONLY, 0)
    movn    x0, #99                 // AT_FDCWD (-100)
    adr     x1, path
    mov     w2, #0
    mov     w3, #0
    mov     x8, #56                 // openat
    svc     #0
    tbnz    x0, #63, fail
    mov     x19, x0                 // fd

    // getdents64(fd, buf, 1024)
    mov     x0, x19
    adr     x1, buf
    mov     x2, #1024
    mov     x8, #61                 // getdents64
    svc     #0
    cmp     x0, #1
    b.lt    fail
    mov     x20, x0                 // bytes returned

    mov     x21, #0                 // offset into buf
scan:
    cmp     x21, x20
    b.ge    fail
    adr     x10, buf
    add     x22, x10, x21           // record pointer
    ldrh    w23, [x22, #16]         // d_reclen
    cbz     w23, fail               // guard against a zero-length record
    add     x24, x22, #19           // d_name

    // compare d_name with "cpuinfo\0" (8 bytes incl. NUL)
    adr     x25, want
    mov     x26, #8
cmpl:
    ldrb    w27, [x24], #1
    ldrb    w28, [x25], #1
    cmp     w27, w28
    b.ne    next
    subs    x26, x26, #1
    b.ne    cmpl
    b       found
next:
    add     x21, x21, x23           // offset += d_reclen
    b       scan

found:
    mov     x0, #0
    b       exit
fail:
    mov     x0, #1
exit:
    mov     x8, #94                 // exit_group
    svc     #0

path:
    .asciz  "/proc"
want:
    .asciz  "cpuinfo"

    .bss
    .balign 8
buf:
    .skip   1024
