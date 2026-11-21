/* Functions made at run time, each called once from the program's own
 * code, through one call site: `add x0, x0, #k`, `ret`, 16 bytes apart, as
 * a JIT makes a function and runs it. The site is linked once, at its
 * first call's fault; from then on a call to a function not translated
 * yet goes into fwe from the site's stub, as a translation's lookup does,
 * rather than faulting again. Every line printed is what Linux prints. */
#include <stdint.h>
int printf(const char *fmt, ...);
void *mmap(void *addr, unsigned long len, int prot, int flags, int fd, long off);

#define N 4000

int main(void) {
    uint32_t *code = mmap(0, 16 * N, 7, 0x22, -1, 0);
    for (long k = 0; k < N; k++) {
        code[4 * k] = 0x91000000 | (uint32_t)(k & 0xfff) << 10; /* add x0, x0, #k */
        code[4 * k + 1] = 0xd65f03c0;                           /* ret */
    }
    for (long k = 0; k < 16 * N; k += 4) {
        __asm__ volatile("dc cvau, %0" ::"r"((char *)code + k));
    }
    __asm__ volatile("dsb ish");
    for (long k = 0; k < 16 * N; k += 4) {
        __asm__ volatile("ic ivau, %0" ::"r"((char *)code + k));
    }
    __asm__ volatile("dsb ish\n"
                     "isb");
    /* The call site: one `blr`, in a loop that runs natively. */
    long sum = 0;
    for (long k = 0; k < N; k++) {
        sum = ((long (*)(long))(code + 4 * k))(sum);
    }
    printf("sum: %ld\n", sum);
    return 0;
}
