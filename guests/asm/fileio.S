// openat(AT_FDCWD, "/probe", O_WRONLY|O_CREAT|O_TRUNC, 0644), write "ok\n",
// close, exit_group(0). Exit 1 on any failure. Exercises the root filesystem.
    .text
    .globl _start
_start:
    movn    x0, #99                 // AT_FDCWD (-100)
    adr     x1, path
    mov     w2, #0x241              // O_WRONLY|O_CREAT|O_TRUNC
    mov     w3, #0x1a4              // 0644
    mov     x8, #56                 // openat
    svc     #0
    tbnz    x0, #63, fail
    mov     x19, x0                 // fd

    mov     x0, x19
    adr     x1, msg
    mov     x2, #(msg_end - msg)
    mov     x8, #64                 // write
    svc     #0
    tbnz    x0, #63, fail

    mov     x0, x19
    mov     x8, #57                 // close
    svc     #0

    mov     x0, #0
    b       exit
fail:
    mov     x0, #1
exit:
    mov     x8, #94                 // exit_group
    svc     #0

path:
    .asciz  "/probe"
msg:
    .ascii  "ok\n"
msg_end:
