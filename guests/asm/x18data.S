// A word among the code that reads as an x18 instruction (`ldr x0, [x18]`)
// but is data: no frame description entry covers it, so the rewrite must
// leave it alone, with section headers or, through PT_GNU_EH_FRAME, without
// them. Exit 0 if it reads back unchanged, 1 otherwise.
    .text
    .globl _start
_start:
    .cfi_startproc
    adr     x1, table
    ldr     w2, [x1]
    movz    w3, #0x0240
    movk    w3, #0xf940, lsl #16
    cmp     w2, w3
    b.ne    fail
    mov     x0, #0
    b       exit
fail:
    mov     x0, #1
exit:
    mov     x8, #94                 // exit_group
    svc     #0
    .cfi_endproc
table:
    .word   0xf9400240              // ldr x0, [x18], as data
