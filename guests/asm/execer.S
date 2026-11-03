// Open a file and keep it at fd 10 (inherited across exec) and fd 11 (marked
// close-on-exec), then build argv/envp on the stack (so no relocations are
// needed) and execve "/execee", which checks what survived. If execve returns,
// it failed: exit 1.
    .text
    .globl _start
_start:
    mov     x0, #-100               // AT_FDCWD
    adr     x1, path
    mov     x2, #0                  // O_RDONLY
    mov     x3, #0
    mov     x8, #56                 // openat
    svc     #0
    tbnz    x0, #63, failed
    mov     x19, x0
    mov     x0, x19
    mov     x1, #10
    mov     x2, #0
    mov     x8, #24                 // dup3(fd, 10, 0): survives exec
    svc     #0
    tbnz    x0, #63, failed
    mov     x0, x19
    mov     x1, #11
    mov     x2, #0x80000            // O_CLOEXEC
    mov     x8, #24                 // dup3(fd, 11, O_CLOEXEC): closed by exec
    svc     #0
    tbnz    x0, #63, failed

    adr     x9, path
    sub     sp, sp, #32
    str     x9, [sp]                // argv[0] = &path
    str     xzr, [sp, #8]           // argv[1] = NULL
    str     xzr, [sp, #16]          // envp[0] = NULL
    adr     x0, path                // pathname
    mov     x1, sp                  // argv
    add     x2, sp, #16             // envp
    mov     x8, #221                // execve
    svc     #0
failed:
    mov     x0, #1                  // execve returned -> failure
    mov     x8, #94
    svc     #0
    .section .rodata
path:
    .asciz  "/execee"
