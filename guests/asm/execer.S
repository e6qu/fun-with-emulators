// Build argv/envp on the stack (so no relocations are needed) and execve
// "/execee". If execve returns, it failed: exit 1.
    .text
    .globl _start
_start:
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
    mov     x0, #1                  // execve returned -> failure
    mov     x8, #94
    svc     #0
path:
    .asciz  "/execee"
