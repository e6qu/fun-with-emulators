/* Code made at run time that keeps values in x16 and x17 (as HotSpot's
 * compiled code does: the procedure call standard lets code use them like
 * any other register between calls) and goes on into other blocks by
 * direct branches with those values live, into words that do not name
 * them first: each such block is entered with the program's own x16 and
 * x17, many times. What it computes is what the same steps compute in C.
 * Every line printed is what Linux prints. */
#include <stddef.h>
#include <stdint.h>

int printf(const char *fmt, ...);
void *memcpy(void *d, const void *s, size_t n);
void *mmap(void *addr, size_t len, int prot, int flags, int fd, long off);

#define ROUNDS 100000

/* long ju_run(long n): x16 and x17 carried round a loop of three blocks,
 * the second and third reached by `b` with them live and starting with an
 * instruction that names neither. */
__asm__(".text\n"
        ".p2align 12\n"
        ".globl ju_begin\n"
        "ju_begin:\n"
        "  mov x2, #0\n"
        "  mov x16, #3\n"
        "  mov x17, #5\n"
        "1:\n"
        "  add x16, x16, x0\n"
        "  b 2f\n"
        "2:\n"
        "  add x2, x2, #1\n"
        "  eor x2, x2, x16\n"
        "  add x17, x17, x2\n"
        "  b 3f\n"
        "3:\n"
        "  add x3, x2, #7\n"
        "  add x2, x3, x17\n"
        "  subs x0, x0, #1\n"
        "  b.ne 1b\n"
        "  eor x0, x2, x16\n"
        "  eor x0, x0, x17\n"
        "  ret\n"
        ".globl ju_end\n"
        "ju_end:\n");
extern const char ju_begin[], ju_end[];

static void flush(void *p, size_t n) {
    uint64_t ctr;
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    uint64_t dline = 4ull << ((ctr >> 16) & 15), iline = 4ull << (ctr & 15);
    uint64_t start = (uint64_t)p, end = start + n;
    for (uint64_t a = start & ~(dline - 1); a < end; a += dline) {
        __asm__ volatile("dc cvau, %0" ::"r"(a) : "memory");
    }
    __asm__ volatile("dsb ish" ::: "memory");
    for (uint64_t a = start & ~(iline - 1); a < end; a += iline) {
        __asm__ volatile("ic ivau, %0" ::"r"(a) : "memory");
    }
    __asm__ volatile("dsb ish\n isb" ::: "memory");
}

/* The same steps in C. */
static long expected(long n) {
    uint64_t x2 = 0, x16 = 3, x17 = 5, x3;
    for (; n != 0; n--) {
        x16 += (uint64_t)n;
        x2 += 1;
        x2 ^= x16;
        x17 += x2;
        x3 = x2 + 7;
        x2 = x3 + x17;
    }
    return (long)(x2 ^ x16 ^ x17);
}

int main(void) {
    size_t len = (size_t)(ju_end - ju_begin);
    char *code = mmap(0, len, 7, 0x22, -1, 0);
    memcpy(code, ju_begin, len);
    flush(code, len);
    long (*run)(long) = (long (*)(long))code;
    long got = run(ROUNDS);
    printf("computed as in C: %s\n", got == expected(ROUNDS) ? "yes" : "no");
    return 0;
}
