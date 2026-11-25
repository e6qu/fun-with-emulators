/* x18 in code made executable at run time, against the same code using x9:
 * one sequence of instructions, assembled twice from one macro, once with
 * x18 as its working register and once with x9, copied into memory mapped
 * writable and executable and run from there. Linux lets a program use
 * x18 like any register (JIT compilers allocate it), so both copies
 * compute the same, quietly and with signals landing anywhere in them.
 * Every line printed is what Linux prints. */
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

int printf(const char *fmt, ...);
void *memcpy(void *d, const void *s, size_t n);
void *memset(void *d, int c, size_t n);
void *mmap(void *addr, size_t len, int prot, int flags, int fd, long off);
int pthread_create(unsigned long *t, const void *attr, void *(*fn)(void *), void *arg);
int pthread_join(unsigned long t, void **ret);
int pthread_kill(unsigned long t, int sig);
unsigned long pthread_self(void);
int usleep(unsigned us);

struct sigaction {
    void (*sa_sigaction)(int, void *, void *);
    unsigned long sa_mask[16];
    int sa_flags;
    void (*sa_restorer)(void);
};
int sigaction(int sig, const struct sigaction *act, struct sigaction *old);

#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define SIGUSR1 10
#define SA_SIGINFO 4
#define SA_RESTART 0x10000000

/* long work(long *data, long v): data has 64 words; v is nonzero. R is the
 * working register, W its 32-bit view. x11 accumulates. */
#define BODY(R, W)                                                         \
    "  stp x29, x30, [sp, #-16]!\n"                                        \
    "  mov x29, sp\n"                                                      \
    "  mov x11, #0\n"                                                      \
    /* arithmetic, shifts, multiply, divide */                             \
    "  mov " R ", x1\n"                                                    \
    "  add " R ", " R ", #3\n"                                             \
    "  add x2, " R ", " R ", lsl #2\n"                                     \
    "  sub " R ", x2, " R "\n"                                             \
    "  eor " R ", " R ", x1, ror #7\n"                                     \
    "  mul " R ", " R ", x2\n"                                             \
    "  udiv x3, " R ", x1\n"                                               \
    "  madd " R ", x3, x2, " R "\n"                                        \
    "  lsr " R ", " R ", #3\n"                                             \
    "  add x11, x11, " R "\n"                                              \
    /* compares, conditional select and increment */                       \
    "  cmp " R ", x2\n"                                                    \
    "  csel " R ", " R ", x2, ne\n"                                        \
    "  cmp " R ", #100\n"                                                  \
    "  cinc " R ", " R ", hi\n"                                            \
    "  eor x11, x11, " R "\n"                                              \
    /* loads and stores: plain, pairs, pre and post index, narrow */       \
    "  str " R ", [x0]\n"                                                  \
    "  ldr x5, [x0]\n"                                                     \
    "  stp " R ", x5, [x0, #16]\n"                                         \
    "  ldp " R ", x6, [x0, #16]\n"                                         \
    "  add x11, x11, x6\n"                                                 \
    "  str " R ", [x0, #32]!\n"                                            \
    "  ldr " R ", [x0], #-32\n"                                            \
    "  ldrb " W ", [x0, #1]\n"                                             \
    "  add x11, x11, " R "\n"                                              \
    "  ldrh " W ", [x0, #2]\n"                                             \
    "  add x11, x11, " R "\n"                                              \
    "  ldrsw " R ", [x0, #4]\n"                                            \
    "  add x11, x11, " R "\n"                                              \
    /* register offset, both as the index and as the value */             \
    "  and " R ", x1, #7\n"                                                \
    "  ldr x7, [x0, " R ", lsl #3]\n"                                      \
    "  add x11, x11, x7\n"                                                 \
    "  str " R ", [x0, " R ", lsl #3]\n"                                   \
    "  ldr x7, [x0, " R ", lsl #3]\n"                                      \
    "  add x11, x11, x7\n"                                                 \
    /* exclusives, acquire and release, atomics */                         \
    "  mov " R ", x11\n"                                                   \
    "  add x8, x0, #48\n"                                                  \
    "1: ldxr x7, [x8]\n"                                                   \
    "  stxr w10, " R ", [x8]\n"                                            \
    "  cbnz w10, 1b\n"                                                     \
    "  ldar " R ", [x8]\n"                                                 \
    "  stlr " R ", [x0]\n"                                                 \
    "  ldadd x1, " R ", [x8]\n"                                            \
    "  add x11, x11, " R "\n"                                              \
    "  ldr x7, [x8]\n"                                                     \
    "  add x11, x11, x7\n"                                                 \
    /* floating point moves */                                             \
    "  fmov d0, " R "\n"                                                   \
    "  fadd d0, d0, d0\n"                                                  \
    "  fmov " R ", d0\n"                                                   \
    "  eor x11, x11, " R "\n"                                              \
    /* the stack pointer, read and written through it */                   \
    "  mov " R ", sp\n"                                                    \
    "  mov x10, sp\n"                                                      \
    "  sub " R ", " R ", x10\n"                                            \
    "  add x11, x11, " R "\n"                                              \
    "  mov " R ", sp\n"                                                    \
    "  mov sp, " R "\n"                                                    \
    /* sp moved through it, and written back by its loads and stores */   \
    "  sub " R ", sp, #64\n"                                               \
    "  mov sp, " R "\n"                                                    \
    "  add " R ", sp, #64\n"                                               \
    "  mov sp, " R "\n"                                                    \
    "  add " R ", x11, #5\n"                                               \
    "  str " R ", [sp, #-16]!\n"                                           \
    "  ldr " R ", [sp], #16\n"                                             \
    "  add x11, x11, " R "\n"                                              \
    "  stp " R ", x5, [sp, #-32]!\n"                                       \
    "  ldp " R ", x6, [sp], #32\n"                                         \
    "  eor x11, x11, " R "\n"                                              \
    /* pc-relative: the difference cancels the copy's place */             \
    "  adr " R ", 2f\n"                                                    \
    "  adr x10, 2f\n"                                                      \
    "  sub " R ", " R ", x10\n"                                            \
    "  add x11, x11, " R "\n"                                              \
    "  ldr " R ", 3f\n"                                                    \
    "  add x11, x11, " R "\n"                                              \
    /* branches on it, and a call through it */                            \
    "  mov " R ", x1\n"                                                    \
    "  cbz " R ", 4f\n"                                                    \
    "  add x11, x11, #1\n"                                                 \
    "4: tbnz " R ", #0, 5f\n"                                              \
    "  add x11, x11, #2\n"                                                 \
    "5: adr " R ", 6f\n"                                                   \
    "  blr " R "\n"                                                        \
    /* read, then a call, in a block entered past a read of sp (with the  \
     * program's x16 and x17 in place) whose first branch comes first */  \
    "  mov " R ", x1\n"                                                    \
    "  add x10, sp, #0\n"                                                  \
    "  b 7f\n"                                                             \
    "7: cbz x1, 8f\n"                                                      \
    "8: add x11, x11, " R "\n"                                             \
    "  bl 6f\n"                                                            \
    "  mov x0, x11\n"                                                      \
    "  ldp x29, x30, [sp], #16\n"                                          \
    "  ret\n"                                                              \
    "6: add x11, x11, #9\n"                                                \
    "  eor x11, x11, x11, lsl #5\n"                                        \
    "  ret\n"                                                              \
    "  .balign 8\n"                                                        \
    "2: .quad 0\n"                                                         \
    "3: .quad 0x0123456789abcdef\n"

__asm__(".arch_extension lse\n"
        ".section .rodata\n"
        ".balign 4096\n"
        ".globl jx_begin\n"
        "jx_begin:\n"
        "jx_x18:\n" BODY("x18", "w18") "jx_x9:\n" BODY("x9", "w9")
        /* long casp_count(long *pair, long n): adds 1 to pair[0] n times
         * with casp on x18 and x19, retrying each until it succeeds. */
        "jx_casp:\n"
        "  stp x19, x20, [sp, #-32]!\n"
        "  str x21, [sp, #16]\n"
        "1: ldp x18, x19, [x0]\n"
        "  mov x4, x18\n"
        "  add x20, x18, #1\n"
        "  mov x21, x19\n"
        "  casp x18, x19, x20, x21, [x0]\n"
        "  cmp x18, x4\n"
        "  b.ne 1b\n"
        "  subs x1, x1, #1\n"
        "  b.ne 1b\n"
        "  ldr x0, [x0]\n"
        "  ldr x21, [sp, #16]\n"
        "  ldp x19, x20, [sp], #32\n"
        "  ret\n"
        ".globl jx_end\n"
        "jx_end:\n"
        ".balign 4096\n"
        ".text\n");

extern const char jx_begin[], jx_end[], jx_x18[], jx_x9[], jx_casp[];

/* Make code just written visible to instruction fetch, as Linux's
 * __clear_cache does, by the cache lines CTR_EL0 gives. */
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

typedef long (*work_fn)(long *, long);

static char *code;
static atomic_int stop;
static atomic_long signals;
static unsigned long target;

/* Where the last signals landed, for a round that disagrees. */
#define UC_PC(ctx) (*(uint64_t *)((char *)(ctx) + 440))
static uint64_t landed[1024];

static void on_usr1(int sig, void *si, void *ctx) {
    (void)sig;
    (void)si;
    long n = atomic_fetch_add(&signals, 1);
    landed[n & 1023] = UC_PC(ctx);
}

static void *signaller(void *arg) {
    (void)arg;
    while (!atomic_load(&stop)) {
        pthread_kill(target, SIGUSR1);
        usleep(20);
    }
    return 0;
}

/* Both copies on the same inputs, each with its own data words: whether
 * they agree in all `rounds`. */
static int agree(int rounds) {
    work_fn x18 = (work_fn)(code + (jx_x18 - jx_begin));
    work_fn x9 = (work_fn)(code + (jx_x9 - jx_begin));
    int same = 0;
    for (int i = 0; i < rounds; i++) {
        long a[64], b[64];
        for (int k = 0; k < 64; k++) {
            a[k] = b[k] = (long)(k * 0x9e3779b97f4a7c15ul + (unsigned long)i);
        }
        long v = (long)(i * 2654435761u) | 1;
        long before = atomic_load(&signals);
        long r18 = x18(a, v), r9 = x9(b, v);
        int ok = r18 == r9 && __builtin_memcmp(a, b, sizeof a) == 0;
        same += ok;
        if (!ok) {
            /* Not printed on Linux, where both copies always agree. */
            long after = atomic_load(&signals);
            printf("round %d: x18 %lx, x9 %lx; signals landed at", i, r18, r9);
            for (long k = before; k < after && k < before + 16; k++) {
                uint64_t pc = landed[k & 1023];
                uint64_t base18 = (uint64_t)(code + (jx_x18 - jx_begin));
                uint64_t base9 = (uint64_t)(code + (jx_x9 - jx_begin));
                if (pc >= base18 && pc < base9) {
                    printf(" x18+%lx", (unsigned long)(pc - base18));
                } else if (pc >= base9 && pc < base9 + (base9 - base18)) {
                    printf(" x9+%lx", (unsigned long)(pc - base9));
                } else {
                    printf(" %lx", (unsigned long)pc);
                }
            }
            for (int k = 0; k < 64; k++) {
                if (a[k] != b[k]) {
                    printf("; data[%d] %lx vs %lx", k, a[k], b[k]);
                }
            }
            printf("\n");
        }
    }
    return same;
}

int main(void) {
    size_t len = (size_t)(jx_end - jx_begin);
    code = mmap(0, len, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memcpy(code, jx_begin, len);
    flush(code, len);

    printf("x18 forms: same in %d of 1000\n", agree(1000));

    struct sigaction usr1 = {0};
    usr1.sa_sigaction = on_usr1;
    usr1.sa_flags = SA_SIGINFO | SA_RESTART;
    sigaction(SIGUSR1, &usr1, 0);
    target = pthread_self();
    unsigned long t;
    pthread_create(&t, 0, signaller, 0);
    int same = agree(100000);
    static _Alignas(16) long pair[2];
    long counted = ((long (*)(long *, long))(code + (jx_casp - jx_begin)))(pair, 2000000);
    atomic_store(&stop, 1);
    pthread_join(t, 0);
    printf("x18 forms with signals: same in %d of 100000, signals %s\n", same,
           atomic_load(&signals) ? "landed" : "none");
    printf("casp on x18 with signals: %ld of 2000000\n", counted);
    return 0;
}
