// fork (clone with just SIGCHLD), child exits 7, parent waits and checks the
// status encodes a normal exit with code 7. Exit 0 on success.
    .text
    .globl _start
_start:
    mov     x0, #17                 // flags = SIGCHLD (a fork)
    mov     x1, #0                  // child_stack (unused for fork)
    mov     x2, #0
    mov     x3, #0
    mov     x4, #0
    mov     x8, #220                // clone
    svc     #0
    tbnz    x0, #63, fail
    cbz     x0, child

    // parent: wait for the child.
    sub     sp, sp, #16
    mov     x0, #-1                 // any child
    mov     x1, sp                  // &status
    mov     x2, #0
    mov     x3, #0
    mov     x8, #260                // wait4
    svc     #0
    tbnz    x0, #63, fail
    ldr     w10, [sp]               // status
    lsr     w10, w10, #8            // decode WEXITSTATUS
    and     x0, x10, #0xff          // exit with the child's reported status
    mov     x8, #94
    svc     #0

child:
    mov     x0, #7
    mov     x8, #94                 // exit_group(7)
    svc     #0

fail:
    mov     x0, #1
    mov     x8, #94                 // exit_group
    svc     #0
