// A library of 140 MiB of zeroed data, loaded before bigcode.S's library so
// that what lies below that library's code is taken, as below LLVM's
// library in clang.
    .bss
    .globl fill
fill:
    .space  140 * 1024 * 1024
