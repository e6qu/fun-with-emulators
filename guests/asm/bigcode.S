// A shared library whose code is longer than a branch reaches (128 MiB):
// two functions reading the thread pointer (each a rewritten site with a
// stub) 150 MiB apart. The first reaches stub room only below the library.
    .text
    .globl first
    .type first, %function
first:
    mrs     x0, tpidr_el0
    ret
    .space  150 * 1024 * 1024
    .globl last
    .type last, %function
last:
    mrs     x0, tpidr_el0
    ret
