// Job control: fork a child, which starts a new session with setsid and
// checks that getsid(0) and getpgid(0) both report the new session id (a
// session leader's sid, pgid and pid coincide). The parent propagates the
// child's exit code, so a passing run exits 0.
    .text
    .globl _start
_start:
    mov     x0, #17                 // flags = SIGCHLD (a fork)
    mov     x1, #0
    mov     x2, #0
    mov     x3, #0
    mov     x4, #0
    mov     x8, #220                // clone
    svc     #0
    tbnz    x0, #63, fail
    cbz     x0, child

    // parent: wait for the child and adopt its exit status.
    sub     sp, sp, #16
    mov     x0, #-1
    mov     x1, sp
    mov     x2, #0
    mov     x3, #0
    mov     x8, #260                // wait4
    svc     #0
    tbnz    x0, #63, fail
    ldr     w10, [sp]
    and     w11, w10, #0x7f         // termination signal
    cbz     w11, exited
    mov     x0, #1                  // child was signalled: failure
    b       fin
exited:
    lsr     w10, w10, #8            // WEXITSTATUS
    and     x0, x10, #0xff
fin:
    mov     x8, #94
    svc     #0

child:
    // setsid() -> new session id
    mov     x8, #157
    svc     #0
    tbnz    x0, #63, cfail
    mov     x19, x0                 // sid

    // getsid(0) == sid
    mov     x0, #0
    mov     x8, #156
    svc     #0
    cmp     x0, x19
    b.ne    cfail

    // getpgid(0) == sid
    mov     x0, #0
    mov     x8, #155
    svc     #0
    cmp     x0, x19
    b.ne    cfail

    mov     x0, #0
    mov     x8, #94                 // exit_group(0)
    svc     #0
cfail:
    mov     x0, #1
    mov     x8, #94
    svc     #0
fail:
    mov     x0, #1
    mov     x8, #94
    svc     #0
