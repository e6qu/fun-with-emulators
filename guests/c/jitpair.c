/* Code made at run time calling, in turn, functions whose addresses differ
 * by a multiple of 4 MiB: a translator that looks targets up by their low
 * bits finds them all in one place. Each call reaches its own function,
 * however many share it. Every line printed is what Linux prints. */
#include <stddef.h>
#include <stdint.h>

int printf(const char *fmt, ...);
void *memcpy(void *d, const void *s, size_t n);
void *mmap(void *addr, size_t len, int prot, int flags, int fd, long off);
int mprotect(void *addr, size_t len, int prot);
#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define MAP_FAILED ((void *)-1)

/* The dispatcher: `acc` through `n` rounds of calls to `f`, `g` and `h`,
 * each adding to it. */
extern const char jp_begin[], jp_end[];
__asm__(".text\n"
        ".globl jp_begin\n"
        "jp_begin:\n"
        "  stp x29, x30, [sp, #-48]!\n"
        "  stp x19, x20, [sp, #16]\n"
        "  stp x21, x22, [sp, #32]\n"
        "  mov x19, x1\n"
        "  mov x20, x2\n"
        "  mov x21, x3\n"
        "  mov x22, x4\n"
        "1:\n"
        "  blr x20\n"
        "  blr x21\n"
        "  blr x22\n"
        "  subs x19, x19, #1\n"
        "  b.ne 1b\n"
        "  ldp x21, x22, [sp, #32]\n"
        "  ldp x19, x20, [sp, #16]\n"
        "  ldp x29, x30, [sp], #48\n"
        "  ret\n"
        ".globl jp_end\n"
        "jp_end:\n");

typedef long (*dispatch)(long acc, long n, void *f, void *g, void *h);

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

#define MIB4 (4ul << 20)
#define LEN (2 * MIB4 + 0x20000)

/* `add x0, x0, #k` then `ret` at `code + off`. */
static void *adder(char *code, size_t off, unsigned k) {
    uint32_t *w = (uint32_t *)(code + off);
    w[0] = 0x91000000u | (k << 10);
    w[1] = 0xd65f03c0u;
    return w;
}

int main(void) {
    char *code = mmap(0, LEN, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code == MAP_FAILED) {
        return 1;
    }
    memcpy(code, jp_begin, (size_t)(jp_end - jp_begin));
    /* Three functions 4 MiB apart, and one elsewhere. */
    void *a = adder(code, 0x10000, 1);
    void *b = adder(code, 0x10000 + MIB4, 2);
    void *c = adder(code, 0x10000 + 2 * MIB4, 4);
    void *other = adder(code, 0x18000, 8);
    flush(code, LEN);
    if (mprotect(code, LEN, PROT_READ | PROT_EXEC) != 0) {
        return 1;
    }
    dispatch d = (dispatch)(void *)code;
    printf("two: %ld\n", d(0, 100000, a, b, other));
    printf("three: %ld\n", d(0, 1000, a, b, c));
    return 0;
}
