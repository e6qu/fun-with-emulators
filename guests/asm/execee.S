// The program execve'd into by execer: fd 10 must have survived the exec and
// fd 11 (close-on-exec) must be gone. Then print a line and exit 0.
    .text
    .globl _start
_start:
    mov     x0, #10
    mov     x1, #1                  // F_GETFD
    mov     x8, #25                 // fcntl
    svc     #0
    tbnz    x0, #63, fail           // fd 10 must be open
    mov     x0, #11
    mov     x1, #1                  // F_GETFD
    mov     x8, #25                 // fcntl
    svc     #0
    tbz     x0, #63, fail           // fd 11 must be closed (EBADF)

    mov     x0, #1
    adr     x1, msg
    mov     x2, #(msg_end - msg)
    mov     x8, #64                 // write
    svc     #0
    mov     x0, #0
    mov     x8, #94                 // exit_group
    svc     #0
fail:
    mov     x0, #1
    mov     x8, #94                 // exit_group
    svc     #0
    .section .rodata
msg:
    .ascii  "exec target ran\n"
msg_end:
