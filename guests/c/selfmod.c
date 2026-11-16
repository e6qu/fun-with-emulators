/* Self-modifying code, as the architecture lets a program write it: an
 * instruction is overwritten, the data cache cleaned and the instruction
 * cache invalidated to the point of unification, then `isb`, after which
 * the new instruction is the one that runs:
 *
 * - an instruction overwritten by the code just before it (in the same
 *   straight run of instructions);
 * - a loop rewriting the immediate of an instruction in its own body on
 *   every pass;
 * - a function of the program's own text, its page made writable and
 *   executable with mprotect, overwritten and called again.
 *
 * Every line printed is what Linux prints. */
#include <stddef.h>
#include <stdint.h>

int printf(const char *fmt, ...);
void *memcpy(void *d, const void *s, size_t n);
void *mmap(void *addr, size_t len, int prot, int flags, int fd, long off);
int mprotect(void *addr, size_t len, int prot);
long sysconf(int name);

#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define _SC_PAGESIZE 30

/* The cache maintenance a write to code needs, for the line at x1 (x1, x9
 * scratch). */
#define SYNC "  dc cvau, x1\n  dsb ish\n  ic ivau, x1\n  dsb ish\n  isb\n"

__asm__(".section .rodata\n"
        ".balign 4096\n"
        ".globl sm_begin\n"
        "sm_begin:\n"

        /* long ahead(void): overwrites `mov x0, #1` just ahead with
         * `mov x0, #42`, then runs on into it. */
        "sm_ahead:\n"
        "  adr x1, 1f\n"
        "  ldr w2, 2f\n"
        "  str w2, [x1]\n" SYNC "1: mov x0, #1\n"
        "  ret\n"
        "2: .word 0xd2800540\n" /* mov x0, #42 */

        /* long loop(long n): on each pass i, sets the immediate of the
         * `add x0, x0, #imm` in its own body to i, then runs it: the sum of
         * 0 .. n - 1. */
        "sm_loop:\n"
        "  mov x3, x0\n"
        "  mov x0, #0\n"
        "  mov x4, #0\n"
        "  adr x1, 4f\n"
        "  ldr w5, 5f\n" /* add x0, x0, #0 */
        "3: lsl x6, x4, #10\n"
        "  orr w2, w5, w6\n"
        "  str w2, [x1]\n" SYNC "4: add x0, x0, #0\n"
        "  add x4, x4, #1\n"
        "  cmp x4, x3\n"
        "  b.ne 3b\n"
        "  ret\n"
        "5: .word 0x91000000\n"

        ".globl sm_end\n"
        "sm_end:\n"
        ".balign 4096\n"

        /* In the program's own text, on a page of its own: long own(void),
         * `mov x0, #1` until overwritten. */
        ".text\n"
        ".balign 16384\n"
        ".globl sm_own\n"
        "sm_own:\n"
        "  mov x0, #1\n"
        "  ret\n"
        ".balign 16384\n");

extern const char sm_begin[], sm_end[], sm_ahead[], sm_loop[];
extern long sm_own(void);

/* Make code just written visible to instruction fetch, as Linux's
 * __clear_cache does, by the cache lines CTR_EL0 gives. */
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

int main(void) {
    size_t len = (size_t)(sm_end - sm_begin);
    char *code = mmap(0, len, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memcpy(code, sm_begin, len);
    flush(code, len);
    long (*ahead)(void) = (long (*)(void))(code + (sm_ahead - sm_begin));
    long (*loop)(long) = (long (*)(long))(code + (sm_loop - sm_begin));

    printf("ahead: %ld\n", ahead());
    /* The second time, it is overwritten with what it already holds. */
    printf("ahead again: %ld\n", ahead());
    printf("loop: %ld\n", loop(100));
    printf("loop again: %ld\n", loop(1000));

    long page = sysconf(_SC_PAGESIZE);
    char *own = (char *)((uintptr_t)sm_own & ~(uintptr_t)(page - 1));
    long before = sm_own();
    int r = mprotect(own, (size_t)page, PROT_READ | PROT_WRITE | PROT_EXEC);
    uint32_t mov7 = 0xd28000e0; /* mov x0, #7 */
    memcpy((void *)sm_own, &mov7, 4);
    flush((void *)sm_own, 4);
    printf("own text: %ld, then %ld (mprotect %d)\n", before, sm_own(), r);
    return 0;
}
