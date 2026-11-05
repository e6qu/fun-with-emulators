// A mapping placed with MAP_FIXED over memory already mapped replaces it,
// as on Linux: the new pages read as zero, the rest of the old mapping
// keeps its data, and one buffer across both is one buffer to the kernel.
// Also a page whose protection is widened by mprotect after a read takes
// the write, and a MAP_FIXED mapping over the program's own image (linked
// low, its memory backed elsewhere by fwe's VM backend) reads as zero and
// takes writes. Writes 4096 'A's and 4096 'B's, then a line per check;
// exits 0, or 1 on a failed check.
    .text
    .globl _start
_start:
    // Two pages of anonymous memory, filled with 'A'.
    mov     x0, #0
    mov     x1, #8192
    mov     x2, #3                  // PROT_READ | PROT_WRITE
    mov     x3, #0x22               // MAP_PRIVATE | MAP_ANONYMOUS
    mov     x4, #-1
    mov     x5, #0
    mov     x8, #222                // mmap
    svc     #0
    tbnz    x0, #63, fail
    mov     x19, x0
    mov     x9, x19
    mov     x10, #8192
    mov     w11, #'A'
1:  strb    w11, [x9], #1
    subs    x10, x10, #1
    b.ne    1b

    // A new mapping over the second page.
    add     x0, x19, #4096
    mov     x1, #4096
    mov     x2, #3
    mov     x3, #0x32               // MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED
    mov     x4, #-1
    mov     x5, #0
    mov     x8, #222
    svc     #0
    add     x9, x19, #4096
    cmp     x0, x9
    b.ne    fail
    // It reads as zero; the first page kept its data.
    mov     x10, #4096
2:  ldrb    w11, [x9], #1
    cbnz    w11, fail
    subs    x10, x10, #1
    b.ne    2b
    ldrb    w11, [x19, #4095]
    cmp     w11, #'A'
    b.ne    fail
    // Filled with 'B', both pages go out in one write.
    add     x9, x19, #4096
    mov     x10, #4096
    mov     w11, #'B'
3:  strb    w11, [x9], #1
    subs    x10, x10, #1
    b.ne    3b
    mov     x0, #1
    mov     x1, x19
    mov     x2, #8192
    mov     x8, #64                 // write
    svc     #0
    cmp     x0, #2, lsl #12
    b.ne    fail
    adr     x1, m_span
    mov     x2, #(m_span_end - m_span)
    bl      print

    // A read-only page, read, then made writable: the write goes in.
    mov     x0, #0
    mov     x1, #4096
    mov     x2, #1                  // PROT_READ
    mov     x3, #0x22
    mov     x4, #-1
    mov     x5, #0
    mov     x8, #222
    svc     #0
    tbnz    x0, #63, fail
    mov     x20, x0
    ldr     x9, [x20]
    cbnz    x9, fail
    mov     x0, x20
    mov     x1, #4096
    mov     x2, #3
    mov     x8, #226                // mprotect
    svc     #0
    cbnz    x0, fail
    mov     x9, #42
    str     x9, [x20]
    ldr     x9, [x20]
    cmp     x9, #42
    b.ne    fail
    adr     x1, m_widened
    mov     x2, #(m_widened_end - m_widened)
    bl      print

    // A new mapping over a page of the program's own data.
    adr     x21, image_page
    mov     x9, #7
    str     x9, [x21]
    mov     x0, x21
    mov     x1, #4096
    mov     x2, #3
    mov     x3, #0x32
    mov     x4, #-1
    mov     x5, #0
    mov     x8, #222
    svc     #0
    cmp     x0, x21
    b.ne    fail
    ldr     x9, [x21]
    cbnz    x9, fail
    mov     x9, #9
    str     x9, [x21]
    ldr     x9, [x21]
    cmp     x9, #9
    b.ne    fail
    adr     x1, m_image
    mov     x2, #(m_image_end - m_image)
    bl      print

    mov     x0, #0
    b       exit

fail:
    mov     x0, #1
exit:
    mov     x8, #94                 // exit_group
    svc     #0

// write(1, x1, x2)
print:
    mov     x0, #1
    mov     x8, #64
    svc     #0
    ret

    .section .rodata
m_span:     .ascii "\nmap_fixed: replaces, and a buffer across both is one\n"
m_span_end:
m_widened:  .ascii "mprotect: a widened page takes the write\n"
m_widened_end:
m_image:    .ascii "map_fixed: over the program's own data\n"
m_image_end:

    .data
    .balign 4096
image_page:
    .fill   4096, 1, 0x55
