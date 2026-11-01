// write(1, "hello from linux\n") then exit_group(0).
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
    .ascii  "hello from linux\n"
message_end:
