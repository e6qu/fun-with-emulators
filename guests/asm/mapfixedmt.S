// MAP_FIXED replacing memory 200 times while a second thread runs guest
// code that reads the same mapping: each new page reads as zero (the
// other thread's vCPU is stopped while fwe's VM backend reuses the memory).
// Prints "ok"; exits 0, or 1 if a new page held data.
    .text
    .globl _start
_start:
    // A stack for the thread.
    mov x0,#0; mov x1,#65536; mov x2,#3; mov x3,#0x22; mov x4,#-1; mov x5,#0; mov x8,#222; svc #0
    add x20, x0, #65536
    // Two pages; the second is replaced.
    mov x0,#0; mov x1,#8192; mov x2,#3; mov x3,#0x22; mov x4,#-1; mov x5,#0; mov x8,#222; svc #0
    mov x19, x0
    adr x21, flag
    // clone(CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM = 0x50f00, stack)
    movz x0, #0x0f00
    movk x0, #0x5, lsl #16
    mov x1, x20; mov x2,#0; mov x3,#0; mov x4,#0; mov x8,#220; svc #0
    cbz x0, thread
    mov x22, #200
loop:
    add x0, x19, #4096; mov x1,#4096; mov x2,#3; mov x3,#0x32; mov x4,#-1; mov x5,#0; mov x8,#222; svc #0
    add x23, x19, #4096; ldrb w9, [x23]
    cbnz w9, bad
    mov w9, #1
    strb w9, [x23]
    subs x22, x22, #1
    b.ne loop
    mov w9,#1; str w9,[x21]
    adr x1, ok; mov x2,#3; mov x0,#1; mov x8,#64; svc #0
    mov x0,#0; mov x8,#94; svc #0
bad:
    mov x0,#1; mov x8,#94; svc #0
thread:
1:  ldr w9, [x21]
    ldrb w10, [x19]
    cbz w9, 1b
    mov x0,#0; mov x8,#93; svc #0
    .data
flag: .word 0
ok: .ascii "ok\n"
