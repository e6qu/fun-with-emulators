// A jump table through x18, as clang makes one where x18 is free (V8's
// ExternalReferenceTable::Init in Electron): adr x18 to the table, the
// index loaded through x16 and x17 between, add the scaled index, br x18
// to a branch to the case, x16 and x17 live across the branch (the cases
// and the next round read them). Each index reaches its own case; then a
// call through x18 (blr x18) returns. Exit 0 if every case and the call
// are reached as written and x16 and x17 hold their values, 1 otherwise.
    .text
    .globl _start
_start:
    adr     x16, indexes            // the table of indexes, live throughout
    mov     x19, #0                 // the round
next:
    mov     x17, x19
    adr     x18, table
    ldrb    w0, [x16, x17]
    add     x18, x18, x0, lsl #2
    mov     x17, #0x717            // live into the case
    br      x18
table:
    b       case0
    b       case1
    b       case2
    b       case3
case0:
    mov     x22, #100
    b       check
case1:
    mov     x22, #101
    b       check
case2:
    mov     x22, #102
    b       check
case3:
    mov     x22, #103
check:
    cmp     x17, #0x717
    b.ne    fail
    adr     x1, indexes
    cmp     x16, x1
    b.ne    fail
    add     x1, x19, #100
    cmp     x22, x1
    b.ne    fail
    add     x19, x19, #1
    cmp     x19, #4
    b.ne    next

    // A call through x18.
    mov     x22, #0
    adr     x18, callee
    blr     x18
    cmp     x22, #7
    b.ne    fail
    mov     x0, #0
    b       exit
callee:
    mov     x22, #7
    ret
fail:
    mov     x0, #1
    b       exit
indexes:
    .byte   0, 1, 2, 3
    .balign 4
exit:
    mov     x8, #94                 // exit_group
    svc     #0
