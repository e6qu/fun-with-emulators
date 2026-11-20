/* Code made at run time looping within itself: a loop whose body skips an
 * instruction on every other turn, its way back and its skip both
 * conditional branches to its own instructions. A translator that goes on
 * to its own translation of each target runs it as one block. Every line
 * printed is what Linux prints. */
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

/* long f(long n): the sum of k for k from n down to 1, and 1 more for each
 * odd k. */
static const uint32_t loop[] = {
    0xd2800001, /* mov x1, #0 */
    0x8b000021, /* 1: add x1, x1, x0 */
    0x36000040, /* tbz x0, #0, 2f */
    0x91000421, /* add x1, x1, #1 */
    0xf1000400, /* 2: subs x0, x0, #1 */
    0x54ffff81, /* b.ne 1b */
    0xaa0103e0, /* mov x0, x1 */
    0xd65f03c0, /* ret */
};

int main(void) {
    uint32_t *code = mmap(0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS,
                          -1, 0);
    if (code == MAP_FAILED) {
        return 1;
    }
    for (size_t i = 0; i < sizeof loop / sizeof loop[0]; i++) {
        code[i] = loop[i];
    }
    flush(code, sizeof loop);
    long n = 1000000;
    long sum = ((long (*)(long))(void *)code)(n);
    printf("loop: %s\n", sum == n * (n + 1) / 2 + n / 2 ? "summed" : "wrong");
    return 0;
}
