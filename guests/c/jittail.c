/* Branches (not calls) through a register into code made at run time, from
 * the program's own code, many times over: a tail call, as an interpreter
 * makes into a JIT's compiled code. Where nothing tells fwe the branch's
 * site, it follows where the code returns, so the code that branched in
 * runs by translation from then on and its later branches in are lookups.
 * Every line printed is what Linux prints. */
#include <stdint.h>
int printf(const char *fmt, ...);
void *mmap(void *addr, unsigned long len, int prot, int flags, int fd, long off);

static uint32_t *code;

/* A tail call through x9 into `f`, which returns to this one's caller. */
__attribute__((naked, noinline)) static long jump(void *f, long v) {
    __asm__ volatile("mov x9, x0\n"
                     "mov x0, x1\n"
                     "br x9");
}

int main(void) {
    code = mmap(0, 16384, 7, 0x22, -1, 0);
    code[0] = 0x91000400; /* add x0, x0, #1 */
    code[1] = 0xd65f03c0; /* ret */
    __asm__ volatile("dc cvau, %0\n"
                     "ic ivau, %0\n"
                     "dsb ish\n"
                     "isb" ::"r"(code));
    long sum = 0;
    for (long i = 0; i < 100000; i++) {
        sum += jump(code, i);
    }
    printf("sum: %ld\n", sum);
    return 0;
}
