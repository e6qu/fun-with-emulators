/* Branches (not calls) through a register into code made at run time, from
 * the program's own code, many times over: a tail call, as a runtime's
 * entry stub makes into a JIT's compiled code (past branches of its
 * own), from a function called from a loop a level above. The branch's site, found from the call that
 * led to it, looks its targets up from then on, as a translation does.
 * Every line printed is what Linux prints. */
#include <stdint.h>
int printf(const char *fmt, ...);
void *mmap(void *addr, unsigned long len, int prot, int flags, int fd, long off);

static uint32_t *code;

/* A tail call through x9 into `f`, which returns to this one's caller,
 * past a conditional branch and a branch back, as a runtime's entry stub
 * checks what it calls first. */
__attribute__((naked, noinline)) static long jump(void *f, long v) {
    __asm__ volatile("cbnz x0, 2f\n"
                     "1: mov x0, xzr\n"
                     "ret\n"
                     "2: tbnz x0, #0, 1b\n"
                     "b 3f\n"
                     "nop\n"
                     "3: mov x9, x0\n"
                     "mov x0, x1\n"
                     "br x9");
}

static volatile long last;

/* The call into `jump`, returning to a loop that runs natively. */
__attribute__((noinline)) static long step(long i) {
    long r = jump(code, i);
    last = r;
    return r;
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
        sum += step(i);
    }
    printf("sum: %ld\n", sum);
    return 0;
}
