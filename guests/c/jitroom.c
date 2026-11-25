/* Code made at run time whose every instruction expands the most: functions
 * of back-to-back calls through x16, each translated into one block many
 * times its size. With a small code cache (FWE_JIT_CHUNK) such blocks land
 * at every place in it, the last one too: a translator gives each the
 * room it takes. Every line printed is what Linux prints. */
#include <stddef.h>
#include <stdint.h>

int printf(const char *fmt, ...);
void *mmap(void *addr, size_t len, int prot, int flags, int fd, long off);
#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define MAP_FAILED ((void *)-1)

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

#define FUNCTIONS 64
/* Function `f`'s calls: 39 to 53, so its block's size differs from the
 * last's and the blocks land at every place in a chunk (these sizes put one
 * past the last 6 KiB of a 64 KiB chunk). */
static int calls(int f) { return 39 + f * 18 % 15; }

int main(void) {
    size_t len = 4096 + FUNCTIONS * 4 * 128;
    uint32_t *code = mmap(0, len, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS,
                          -1, 0);
    if (code == MAP_FAILED) {
        return 1;
    }
    /* The callee: `add x0, x0, #1; ret`. */
    code[0] = 0x91000400u;
    code[1] = 0xd65f03c0u;
    for (int f = 0; f < FUNCTIONS; f++) {
        uint32_t *w = code + 1024 + f * 128;
        int k = 0;
        w[k++] = 0xa9bf7bfdu; /* stp x29, x30, [sp, #-16]! */
        w[k++] = 0x910003fdu; /* mov x29, sp */
        w[k++] = 0xaa0103f0u; /* mov x16, x1 */
        for (int c = 0; c < calls(f); c++) {
            w[k++] = 0xd63f0200u; /* blr x16 */
        }
        w[k++] = 0xa8c17bfdu; /* ldp x29, x30, [sp], #16 */
        w[k++] = 0xd65f03c0u; /* ret */
    }
    flush(code, len);
    long sum = 0, want = 0;
    for (int round = 0; round < 3; round++) {
        for (int f = 0; f < FUNCTIONS; f++) {
            long (*fn)(long, void *) = (long (*)(long, void *))(void *)(code + 1024 + f * 128);
            sum = fn(sum, code);
            want += calls(f);
        }
    }
    printf("calls: %s\n", sum == want ? "every one made" : "some lost");
    return 0;
}
