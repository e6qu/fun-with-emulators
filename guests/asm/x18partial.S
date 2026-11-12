// x18 in code the unwind table does not describe, in a program whose table
// describes little (one small function, as musl's has entries for its
// assembly only): it is code all the same, rewritten, so x18 survives
// preemption. Exits 0 if it does, 1 otherwise.
    .text
    .globl _start
_start:
    movz    x18, #0x1818
    movk    x18, #0x1818, lsl #48
    mov     x10, x18
    movz    x19, #0x1000, lsl #16
spin:
    cmp     x18, x10
    b.ne    fail
    subs    x19, x19, #1
    b.ne    spin
    mov     x0, #0
    b       leave
fail:
    mov     x0, #1
leave:
    bl      done

// The one function the unwind table describes.
done:
    .cfi_startproc
    mov     x8, #94                 // exit_group
    svc     #0
    .cfi_endproc
