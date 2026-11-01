// A position-independent executable with a PT_INTERP, so fwe treats it as
// dynamically linked. Prints a line and exits; uses only pc-relative data,
// so it needs no relocations.
    .text
    .globl _start
_start:
    mov     x0, #1
    adr     x1, message
    mov     x2, #(message_end - message)
    mov     x8, #64                 // write
    svc     #0
    mov     x0, #0
    mov     x8, #94                 // exit_group
    svc     #0
message:
    .ascii  "dynamic handoff ok\n"
message_end:
