/* Code made at run time calling a function of the program's own file
 * through a register, again and again: its return address is the made
 * code's own, so the function runs by translation too. Every line printed
 * is what Linux prints. */
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

/* A function of the program's file, with a loop and a branch of its own. */
__attribute__((noinline)) long spread(long x) {
    long s = 0;
    for (long k = 0; k < 8; k++) {
        s += (x >> k) & 1 ? k : 1;
    }
    return s;
}

/* long f(long x, long (*g)(long)): g(x) + 1, made as the program runs. */
static const uint32_t caller[] = {
    0xa9bf7bfd, /* stp x29, x30, [sp, #-16]! */
    0x910003fd, /* mov x29, sp */
    0xd63f0020, /* blr x1 */
    0x91000400, /* add x0, x0, #1 */
    0xa8c17bfd, /* ldp x29, x30, [sp], #16 */
    0xd65f03c0, /* ret */
};

int main(void) {
    uint32_t *code = mmap(0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS,
                          -1, 0);
    if (code == MAP_FAILED) {
        return 1;
    }
    for (size_t i = 0; i < sizeof caller / sizeof caller[0]; i++) {
        code[i] = caller[i];
    }
    flush(code, sizeof caller);
    long (*f)(long, long (*)(long)) = (long (*)(long, long (*)(long)))(void *)code;
    long sum = 0, want = 0;
    for (long i = 0; i < 1000; i++) {
        sum += f(i, spread);
        want += spread(i) + 1;
    }
    printf("calls into the file: %s\n", sum == want ? "summed" : "wrong");
    return 0;
}
