// Virtual credentials: as root, drop to uid 1000 and confirm getuid/geteuid
// report it, then confirm regaining root fails. Exit 0 on success.
    .text
    .globl _start
_start:
    mov     x0, #1000
    mov     x8, #146                // setuid
    svc     #0
    tbnz    x0, #63, fail

    mov     x8, #174                // getuid
    svc     #0
    cmp     x0, #1000
    b.ne    fail

    mov     x8, #175                // geteuid
    svc     #0
    cmp     x0, #1000
    b.ne    fail

    // setuid(0) must now fail (no longer privileged): expect a negative errno.
    mov     x0, #0
    mov     x8, #146                // setuid
    svc     #0
    tbnz    x0, #63, ok
    b       fail
ok:
    mov     x0, #0
    b       exit
fail:
    mov     x0, #1
exit:
    mov     x8, #94                 // exit_group
    svc     #0
