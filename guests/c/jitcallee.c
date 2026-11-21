/* Calls from code made at run time into code made at run time through a
 * `bl`, the callee rewritten (its cache line flushed) before each round,
 * with another thread's signals landing all along: each call reaches the
 * callee as that round wrote it, the callee sees the program's own return
 * address in x30 and the caller's x16, and a signal landing in the
 * callee's words (its first a call reaches with x30 not set yet, under a
 * translator that sets it there) sees that return address in x30 too.
 * Every line printed is what Linux prints. */
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

int printf(const char *fmt, ...);
void *memcpy(void *d, const void *s, size_t n);
void *mmap(void *addr, size_t len, int prot, int flags, int fd, long off);
int pthread_create(unsigned long *t, const void *attr, void *(*fn)(void *), void *arg);
int pthread_join(unsigned long t, void **ret);
int pthread_kill(unsigned long t, int sig);
unsigned long pthread_self(void);

struct sigaction {
    void (*sa_sigaction)(int, void *, void *);
    unsigned long sa_mask[16];
    int sa_flags;
    void (*sa_restorer)(void);
};
int sigaction(int sig, const struct sigaction *act, struct sigaction *old);

#define SIGUSR1 10
#define SA_SIGINFO 4
#define SA_RESTART 0x10000000
#define ROUNDS 8
#define CALLS 50000

/* long caller(long n, long k): n calls of the callee, x16 set to 0x5a5a
 * first; how many came back with x0 other than their return address or x5
 * other than x16 + k. The callee, a page later: x0 = x30, x5 = x16 + k
 * (its immediate rewritten each round). */
__asm__(".text\n"
        ".p2align 14\n"
        ".globl jc_begin\n"
        "jc_begin:\n"
        "  stp x29, x30, [sp, #-16]!\n"
        "  mov x29, sp\n"
        "  mov x2, #0\n"
        "  mov x3, x0\n"
        "  mov x16, #0x5a5a\n"
        "  add x6, x16, x1\n"
        "1:\n"
        "  bl jc_callee\n"
        ".globl jc_back\n"
        "jc_back:\n"
        "  adr x4, jc_back\n"
        "  cmp x0, x4\n"
        "  cinc x2, x2, ne\n"
        "  cmp x5, x6\n"
        "  cinc x2, x2, ne\n"
        "  subs x3, x3, #1\n"
        "  b.ne 1b\n"
        "  mov x0, x2\n"
        "  ldp x29, x30, [sp], #16\n"
        "  ret\n"
        ".p2align 12\n"
        ".globl jc_callee\n"
        "jc_callee:\n"
        "  mov x0, x30\n"
        "  add x5, x16, #0\n"
        "  ret\n"
        ".globl jc_end\n"
        "jc_end:\n");
extern const char jc_begin[], jc_back[], jc_callee[], jc_end[];

static char *code;
static atomic_long signals, wrong_x30;
static atomic_int stop;
static unsigned long target;

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

/* The signal's pc and x30 in Linux's arm64 ucontext. */
#define UC_PC(ctx) (*(uint64_t *)((char *)(ctx) + 440))
#define UC_X30(ctx) (*(uint64_t *)((char *)(ctx) + 184 + 8 * 30))

static void on_usr1(int sig, void *si, void *ctx) {
    (void)sig;
    (void)si;
    atomic_fetch_add(&signals, 1);
    uint64_t callee = (uint64_t)(code + (jc_callee - jc_begin));
    uint64_t back = (uint64_t)(code + (jc_back - jc_begin));
    uint64_t pc = UC_PC(ctx);
    if (pc >= callee && pc < callee + 12 && UC_X30(ctx) != back) {
        atomic_fetch_add(&wrong_x30, 1);
    }
}

/* As fast as they go: a signal lands in the callee's first word (the
 * call entry, one of some twenty a call runs) only one time in fifty. */
static void *signaller(void *arg) {
    (void)arg;
    while (!atomic_load(&stop)) {
        pthread_kill(target, SIGUSR1);
    }
    return 0;
}

int main(void) {
    size_t len = (size_t)(jc_end - jc_begin);
    code = mmap(0, len, 7, 0x22, -1, 0);
    memcpy(code, jc_begin, len);
    flush(code, len);
    struct sigaction usr1 = {0};
    usr1.sa_sigaction = on_usr1;
    usr1.sa_flags = SA_SIGINFO | SA_RESTART;
    sigaction(SIGUSR1, &usr1, 0);
    target = pthread_self();
    unsigned long t;
    pthread_create(&t, 0, signaller, 0);
    long (*caller)(long, long) = (long (*)(long, long))code;
    uint32_t *add = (uint32_t *)(code + (jc_callee - jc_begin)) + 1;
    long wrong = 0;
    for (long k = 1; k <= ROUNDS; k++) {
        *add = 0x91000205 | (uint32_t)k << 10; /* add x5, x16, #k */
        flush(add, 4);
        wrong += caller(CALLS, k);
    }
    atomic_store(&stop, 1);
    pthread_join(t, 0);
    printf("wrong calls: %ld of %d\n", wrong, ROUNDS * CALLS);
    printf("signals in the callee with another x30: %ld, signals %s\n", atomic_load(&wrong_x30),
           atomic_load(&signals) ? "landed" : "none");
    return 0;
}
