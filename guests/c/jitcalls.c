/* Calls into code made at run time from many call sites of the program's
 * own code, each a blr through a register of its own, from several threads
 * at once: fwe links each site to the code's translation once it has
 * called in, and every call still reaches its own target. Every line
 * printed is what Linux prints. */
#include <stdint.h>
int printf(const char *fmt, ...);
void *mmap(void *addr, unsigned long len, int prot, int flags, int fd, long off);
int pthread_create(unsigned long *t, const void *attr, void *(*fn)(void *), void *arg);
int pthread_join(unsigned long t, void **ret);

static uint32_t *code;

#define SITE(r)                                                             \
    static long site##r(void *f, long v) {                                 \
        register long x0 __asm__("x0") = v;                                 \
        register void *t __asm__("x" #r) = f;                               \
        __asm__ volatile("blr %1" : "+r"(x0) : "r"(t) : "x30", "memory");   \
        return x0;                                                          \
    }
SITE(1) SITE(2) SITE(3) SITE(4) SITE(5) SITE(6) SITE(7) SITE(8)
SITE(9) SITE(10) SITE(11) SITE(12) SITE(13) SITE(14) SITE(15)

typedef long (*site_fn)(void *, long);
static site_fn sites[] = {site1, site2, site3, site4, site5, site6, site7, site8,
                          site9, site10, site11, site12, site13, site14, site15};
#define NS (int)(sizeof sites / sizeof sites[0])
static long bad;

static void *run(void *arg) {
    long id = (long)arg;
    for (int i = 0; i < 20000; i++) {
        int k = (i + (int)id) % NS;
        long r = sites[k](code + 4 * k, i);
        if (r != i + k + 1) {
            __atomic_add_fetch(&bad, 1, __ATOMIC_RELAXED);
        }
    }
    return 0;
}

int main(void) {
    code = mmap(0, 16384, 7, 0x22, -1, 0);
    for (int k = 0; k < NS; k++) {
        code[4 * k] = 0x91000000 | ((uint32_t)(k + 1) << 10); /* add x0, x0, #k+1 */
        code[4 * k + 1] = 0xd65f03c0;                          /* ret */
    }
    for (int k = 0; k < 4 * 4 * NS; k += 4) {
        __asm__ volatile("dc cvau, %0" ::"r"((char *)code + k));
        __asm__ volatile("ic ivau, %0" ::"r"((char *)code + k));
    }
    __asm__ volatile("dsb ish");
    __asm__ volatile("isb");
    unsigned long t[4];
    for (long i = 0; i < 4; i++) {
        pthread_create(&t[i], 0, run, (void *)i);
    }
    for (int i = 0; i < 4; i++) {
        pthread_join(t[i], 0);
    }
    printf("wrong calls: %ld\n", bad);
    return 0;
}
