// clone3: a thread made from a struct clone_args (stack and its size, TLS,
// parent and child tid words). The child checks its thread pointer and that
// it runs at the top of the stack it was given, records the result and exits;
// the parent checks the parent tid word, joins on the CLONE_CHILD_CLEARTID
// futex and checks the result. Then a too-small structure is EINVAL and a
// pidfd request with a null address for the descriptor EFAULT. Exit 0 on
// success.
    .text
    .globl _start
_start:
    adr     x9, args
    adr     x10, ctid
    str     x10, [x9, #16]          // child_tid
    adr     x10, ptid
    str     x10, [x9, #24]          // parent_tid
    adr     x10, cstack
    str     x10, [x9, #40]          // stack (lowest address)
    mov     x0, x9                  // &args
    mov     x1, #88                 // sizeof(struct clone_args)
    mov     x8, #435                // clone3
    svc     #0
    tbnz    x0, #63, fail
    cbz     x0, child

    adr     x9, ptid                // CLONE_PARENT_SETTID wrote the tid
    ldr     w10, [x9]
    cmp     w10, w0
    b.ne    fail
parent_wait:
    adr     x0, ctid
    mov     x1, #128                // FUTEX_WAIT | FUTEX_PRIVATE_FLAG
    mov     x2, #1                  // expected sentinel value
    mov     x3, #0                  // no timeout
    mov     x8, #98                 // futex
    svc     #0
    adr     x9, ctid
    ldr     w10, [x9]
    cmp     w10, #1
    b.eq    parent_wait             // spurious wake: still running
    adr     x9, result
    ldr     w10, [x9]
    movz    w11, #0x1234
    cmp     w10, w11
    b.ne    fail

    // size below CLONE_ARGS_SIZE_VER0: EINVAL
    adr     x0, args
    mov     x1, #32
    mov     x8, #435
    svc     #0
    cmn     x0, #22
    b.ne    fail
    // CLONE_PIDFD with nowhere to put the descriptor: EFAULT
    adr     x0, pidfd_args
    mov     x1, #64
    mov     x8, #435
    svc     #0
    cmn     x0, #14
    b.ne    fail
    mov     x0, #0
    b       exit

child:
    movz    w10, #0x0bad            // assume failure
    mrs     x11, tpidr_el0
    movz    x12, #0x5a5a
    cmp     x11, x12
    b.ne    record
    mov     x11, sp
    adr     x12, cstack_top
    cmp     x11, x12
    b.ne    record
    movz    w10, #0x1234
record:
    adr     x9, result
    str     w10, [x9]
    mov     x0, #0
    mov     x8, #93                 // exit (this thread)
    svc     #0

fail:
    mov     x0, #1
exit:
    mov     x8, #94                 // exit_group
    svc     #0

    .data
    .balign 8
args:
    // CLONE_VM | FS | FILES | SIGHAND | THREAD | SYSVSEM | SETTLS
    //   | PARENT_SETTID | CHILD_CLEARTID
    .quad   0x3d0f00                // flags
    .quad   0                       // pidfd
    .quad   0                       // child_tid (filled in)
    .quad   0                       // parent_tid (filled in)
    .quad   0                       // exit_signal
    .quad   0                       // stack (filled in)
    .quad   16384                   // stack_size
    .quad   0x5a5a                  // tls
    .quad   0, 0, 0                 // set_tid, set_tid_size, cgroup
pidfd_args:
    .quad   0x1000                  // CLONE_PIDFD
    .quad   0, 0, 0, 17, 0, 0, 0
    .balign 4
result:
    .word   0
ptid:
    .word   0
ctid:
    .word   1                       // join sentinel

    .bss
    .balign 16
cstack:
    .skip   16384
cstack_top:
