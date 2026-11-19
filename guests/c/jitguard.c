/* Code made at run time that reads a word of data kept in its own cache
 * line, which the program changes and flushes between calls, as a JIT
 * arms and disarms a method's guard (HotSpot's nmethod entry barrier):
 * the line's instructions never change, only the word beside them. A
 * translator that drops the code's translation at each flush goes into
 * the translator at each call after one. Every line printed is what
 * Linux prints. */
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

#define ROUNDS 2000

int main(void) {
    uint32_t *code = mmap(0, 1 << 16, PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code == MAP_FAILED) {
        return 1;
    }
    /* `guard()`: the word two past its first, `ldr w0, 1f; ret; 1:`. */
    code[0] = 0x18000040u; /* ldr w0, #8 */
    code[1] = 0xd65f03c0u; /* ret */
    code[2] = 0;
    flush(code, 12);
    uint32_t (*guard)(void) = (uint32_t (*)(void))(void *)code;
    uint64_t sum = 0;
    for (uint32_t r = 0; r < ROUNDS; r++) {
        code[2] = r;
        flush(&code[2], 4);
        sum += guard();
    }
    printf("sum: %llu\n", (unsigned long long)sum);
    return 0;
}
