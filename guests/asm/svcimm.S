// System calls made with `svc` immediates other than 0, which Linux takes
// as system calls all the same: write(1, "svc imm\n") with `svc #0x80`
// (macOS's own form) and exit_group(0) with `svc #1`. The unwind table
// covers the code, so fwe knows these words are instructions.
    .text
    .globl _start
_start:
    .cfi_startproc
    mov     x0, #1
    adr     x1, message
    mov     x2, #(message_end - message)
    mov     x8, #64                 // write
    svc     #0x80
    mov     x0, #0
    mov     x8, #94                 // exit_group
    svc     #1
    .cfi_endproc

    .section .rodata
message:
    .ascii  "svc imm\n"
message_end:
