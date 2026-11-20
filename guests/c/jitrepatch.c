/* Code made at run time whose call site the program rewrites between
 * rounds, as a JIT repoints a call when its target changes (HotSpot's
 * inline caches): a loop calls through one `bl`, which each round points
 * at another function, the cache line flushed. A translator that keeps
 * the loop's head apart from the call must still get to the new target
 * without going into the translator at every call. Every line printed is
 * what Linux prints. */
#include <stddef.h>
#include <stdint.h>

int printf(const char *fmt, ...);
void *memcpy(void *d, const void *s, size_t n);
void *mmap(void *addr, size_t len, int prot, int flags, int fd, long off);
#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define MAP_FAILED ((void *)-1)

/* `loop(n)`: `n` calls through the `bl` at `rp_call`, the results added
 * up. The loop's head is a cache line before the call, so a flush of the
 * call's line leaves the head's words alone. */
extern const char rp_begin[], rp_call[], rp_end[];
__asm__(".text\n"
        ".p2align 6\n"
        ".globl rp_begin\n"
        "rp_begin:\n"
        "  stp x29, x30, [sp, #-32]!\n"
        "  stp x19, x20, [sp, #16]\n"
        "  mov x19, x0\n"
        "  mov x20, #0\n"
        "1:\n"
        "  add x20, x20, #0\n"
        "  .rept 11\n"
        "  nop\n"
        "  .endr\n"
        ".globl rp_call\n"
        "rp_call:\n"
        "  bl rp_call\n"
        "  add x20, x20, x0\n"
        "  subs x19, x19, #1\n"
        "  b.ne 1b\n"
        "  mov x0, x20\n"
        "  ldp x19, x20, [sp, #16]\n"
        "  ldp x29, x30, [sp], #32\n"
        "  ret\n"
        ".globl rp_end\n"
        "rp_end:\n");

/* Make code just written visible to instruction fetch, by the lines
 * CTR_EL0 gives. */
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

#define ROUNDS 40
#define CALLS 2000

int main(void) {
    char *code = mmap(0, 1 << 16, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code == MAP_FAILED) {
        return 1;
    }
    memcpy(code, rp_begin, (size_t)(rp_end - rp_begin));
    /* Two functions: `mov x0, #k` then `ret`. */
    uint32_t *fns = (uint32_t *)(code + 0x1000);
    fns[0] = 0xd2800020u; /* mov x0, #1 */
    fns[1] = 0xd65f03c0u;
    fns[2] = 0xd2800040u; /* mov x0, #2 */
    fns[3] = 0xd65f03c0u;
    uint32_t *call = (uint32_t *)(code + (rp_call - rp_begin));
    long (*loop)(long) = (long (*)(long))(void *)code;
    long sum = 0;
    for (int r = 0; r < ROUNDS; r++) {
        uint32_t *to = fns + 2 * (r & 1);
        *call = 0x94000000u | (uint32_t)((to - call) & 0x3ffffff);
        flush(code, (size_t)(rp_end - rp_begin));
        sum += loop(CALLS);
    }
    printf("sum: %ld\n", sum);
    return 0;
}
