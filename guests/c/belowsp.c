/* Memory below sp is the program's: Linux's system calls, and every
 * instruction fwe rewrites, leave it as it was. Go's runtime.clone keeps a
 * new thread's m, g and start function below the thread's sp across the
 * thread's first system call; Go's frame pointer sits 8 bytes below sp.
 * Each case stores four words in the 32 bytes below sp, runs one
 * instruction of a kind fwe rewrites, and reads them back: a system call
 * (svc), a write and a read of the thread pointer (msr/mrs tpidr_el0), a
 * use of x18, and a cache flush (ic ivau); then the system call again in
 * code made at run time, which runs by translation.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

typedef unsigned long u64;

int printf(const char *fmt, ...);
void *mmap(void *addr, u64 len, int prot, int flags, int fd, long off);
int mprotect(void *addr, u64 len, int prot);

/* The four words below sp after the instruction, xored with what was
 * stored: 0 where each was kept. */
#define CASE(name, insn)                                                     \
    static u64 name(void) {                                                  \
        u64 out[4];                                                          \
        __asm__ volatile("mov x9, sp\n"                                      \
                         "movz x10, #0x1111\n str x10, [x9, #-8]\n"          \
                         "movz x10, #0x2222\n str x10, [x9, #-16]\n"         \
                         "movz x10, #0x3333\n str x10, [x9, #-24]\n"         \
                         "movz x10, #0x4444\n str x10, [x9, #-32]\n"         \
                         insn "\n"                                           \
                         "ldr x10, [x9, #-8]\n str x10, [%0]\n"              \
                         "ldr x10, [x9, #-16]\n str x10, [%0, #8]\n"         \
                         "ldr x10, [x9, #-24]\n str x10, [%0, #16]\n"        \
                         "ldr x10, [x9, #-32]\n str x10, [%0, #24]\n"        \
                         :                                                   \
                         : "r"(out)                                          \
                         : "x0", "x8", "x9", "x10", "x11", "x18", "memory");       \
        return (out[0] ^ 0x1111) | (out[1] ^ 0x2222) | (out[2] ^ 0x3333) |   \
               (out[3] ^ 0x4444);                                            \
    }

CASE(syscall, "movz x8, #172\n svc #0") /* getpid */
CASE(tp_write, "mrs x11, tpidr_el0\n msr tpidr_el0, x11")
CASE(tp_read, "mrs x11, tpidr_el0")
CASE(x18_use, "mov x18, x9\n add x11, x18, #1")
CASE(flush, "ic ivau, x9")

/* Code made at run time: the same, getpid between the stores and the
 * loads, the four words copied to the buffer its argument names. */
static u64 run_time(void) {
    static const unsigned code[] = {
        0xaa0003eb, /* mov x11, x0 */
        0x910003e9, /* mov x9, sp */
        0xd282222a, /* mov x10, #0x1111 */
        0xf81f812a, /* stur x10, [x9, #-8] */
        0xd284444a, /* mov x10, #0x2222 */
        0xf81f012a, /* stur x10, [x9, #-16] */
        0xd286666a, /* mov x10, #0x3333 */
        0xf81e812a, /* stur x10, [x9, #-24] */
        0xd288888a, /* mov x10, #0x4444 */
        0xf81e012a, /* stur x10, [x9, #-32] */
        0xd2801588, /* mov x8, #172 */
        0xd4000001, /* svc #0 */
        0xf85f812a, /* ldur x10, [x9, #-8] */
        0xf900016a, /* str x10, [x11] */
        0xf85f012a, /* ldur x10, [x9, #-16] */
        0xf900056a, /* str x10, [x11, #8] */
        0xf85e812a, /* ldur x10, [x9, #-24] */
        0xf900096a, /* str x10, [x11, #16] */
        0xf85e012a, /* ldur x10, [x9, #-32] */
        0xf9000d6a, /* str x10, [x11, #24] */
        0xd65f03c0, /* ret */
    };
    unsigned *p = mmap(0, 4096, 3, 0x22, -1, 0);
    for (unsigned i = 0; i < sizeof code / 4; i++) p[i] = code[i];
    for (u64 a = (u64)p & ~63ul; a < (u64)(p + sizeof code / 4); a += 64)
        __asm__ volatile("dc cvau, %0\n dsb ish\n ic ivau, %0\n dsb ish" : : "r"(a) : "memory");
    __asm__ volatile("isb" ::: "memory");
    mprotect(p, 4096, 5);
    u64 out[4] = {0};
    ((void (*)(u64 *))p)(out);
    return (out[0] ^ 0x1111) | (out[1] ^ 0x2222) | (out[2] ^ 0x3333) | (out[3] ^ 0x4444);
}

int main(void) {
    printf("below sp after a system call: %s\n", syscall() ? "changed" : "kept");
    printf("after a thread pointer write: %s\n", tp_write() ? "changed" : "kept");
    printf("after a thread pointer read: %s\n", tp_read() ? "changed" : "kept");
    printf("after a use of x18: %s\n", x18_use() ? "changed" : "kept");
    printf("after a cache flush: %s\n", flush() ? "changed" : "kept");
    printf("after a system call in code made at run time: %s\n", run_time() ? "changed" : "kept");
    return 0;
}
