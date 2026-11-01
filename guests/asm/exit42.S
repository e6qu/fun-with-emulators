// exit_group(42).
    .text
    .globl _start
_start:
    mov     x0, #42
    mov     x8, #94                 // exit_group
    svc     #0
