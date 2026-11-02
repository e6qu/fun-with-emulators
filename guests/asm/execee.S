// The program execve'd into by execer: print a line and exit 0.
    .text
    .globl _start
_start:
    mov     x0, #1
    adr     x1, msg
    mov     x2, #(msg_end - msg)
    mov     x8, #64                 // write
    svc     #0
    mov     x0, #0
    mov     x8, #94                 // exit_group
    svc     #0
msg:
    .ascii  "exec target ran\n"
msg_end:
