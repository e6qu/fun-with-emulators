/* A page of the program's own code given other protections, and run
 * after: `live16` keeps a value in x16 across an instruction writing x18,
 * as GCC's code does where x18 is free (git's SHA-1).
 *
 *   bti        the page made executable again, with PROT_BTI where
 *              AT_HWCAP2 reports BTI, as glibc's dynamic linker does to
 *              every object built for BTI
 *   rewritten  the page made writable, then executable again, as a text
 *              relocation does (nothing written)
 *
 * Each prints what `live16` computes before and after, many times after. */
int printf(const char *fmt, ...);
int mprotect(void *addr, unsigned long len, int prot);
int strcmp(const char *a, const char *b);
unsigned long getauxval(unsigned long type);

#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#define PROT_BTI 0x10
#define PAGE 16384
#define AT_HWCAP2 26
#define HWCAP2_BTI (1ul << 17)

long live16(long);

/* On a page of its own, 16 KiB aligned (the largest page Linux on arm64
 * and macOS use), so nothing else that runs is on it. */
__asm__(".text\n"
        ".balign 16384\n"
        ".globl live16\n"
        "live16:\n"
        "  mov x16, x0\n"
        "  add x18, x0, #1\n"
        "  add x0, x16, x18\n"
        "  ret\n"
        ".balign 16384\n");

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("usage: textprotect bti|rewritten\n");
        return 2;
    }
    void *page = (void *)((unsigned long)live16 & ~(unsigned long)(PAGE - 1));
    printf("before: %ld\n", live16(20));
    int r;
    if (strcmp(argv[1], "bti") == 0) {
        int bti = getauxval(AT_HWCAP2) & HWCAP2_BTI ? PROT_BTI : 0;
        r = mprotect(page, PAGE, PROT_READ | PROT_EXEC | bti);
    } else {
        r = mprotect(page, PAGE, PROT_READ | PROT_WRITE);
        if (r == 0) {
            r = mprotect(page, PAGE, PROT_READ | PROT_EXEC);
        }
    }
    printf("mprotect: %d\n", r);
    /* Many times: a translation's branches are linked once taken. */
    long sum = 0;
    for (long i = 0; i < 1000; i++) {
        sum += live16(i);
    }
    printf("after: %ld %ld\n", live16(20), sum);
    return 0;
}
