/* JIT code interrupted everywhere: worker threads run code copied into
 * memory mapped writable and executable (so it runs by translation) that
 * uses every kind of instruction a translation expands, while other
 * threads, all at once:
 *
 * - send the workers signals, whose handler returns;
 * - take away and give back the reading of a page the code loads from
 *   (through x18 too), the fault's handler giving it back;
 * - write data into the code's own page (its translations dropped).
 *
 * A signal or fault landing in the middle of an expansion must leave the
 * code's registers as at its own instruction, so each round's checksum is
 * what a quiet run computed. Every line printed is what Linux prints. */
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

int printf(const char *fmt, ...);
void *memcpy(void *d, const void *s, size_t n);
void *mmap(void *addr, size_t len, int prot, int flags, int fd, long off);
int mprotect(void *addr, size_t len, int prot);
int pthread_create(unsigned long *t, const void *attr, void *(*fn)(void *), void *arg);
int pthread_join(unsigned long t, void **ret);
int pthread_kill(unsigned long t, int sig);
int usleep(unsigned us);

struct sigaction {
    void (*sa_sigaction)(int, void *, void *);
    unsigned long sa_mask[16];
    int sa_flags;
    void (*sa_restorer)(void);
};
int sigaction(int sig, const struct sigaction *act, struct sigaction *old);

#define PROT_NONE 0
#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define SIGUSR1 10
#define SIGSEGV 11
#define SA_SIGINFO 4
#define SA_RESTART 0x10000000
/* si_addr in a siginfo. */
#define SI_ADDR(si) (*(uint64_t *)((char *)(si) + 16))

__asm__(
    ".section .rodata\n"
    ".balign 4096\n"
    ".globl js_begin\n"
    "js_begin:\n"

    /* long work(long n, long *table, long tp, long *poll): a checksum of n
     * rounds of every kind of instruction a translation expands. */
    "js_work:\n"
    "  stp x29, x30, [sp, #-16]!\n"
    "  mov x29, sp\n"
    "  mov x4, x0\n"
    "  mov x9, #0\n"
    "  mov x16, #0x16\n"
    "  mov x17, #0x17\n"
    "1:\n"
    /* x18 as a pointer, and in arithmetic */
    "  mov x18, x1\n"
    "  ldr x10, [x18, #8]\n"
    "  add x9, x9, x10\n"
    "  add x18, x18, #16\n"
    "  ldr x10, [x18]\n"
    "  eor x9, x9, x10\n"
    "  ldr x12, [x18, #-16]\n"
    "  add x9, x9, x12\n"
    /* the thread pointer (the caller's, so it cancels) */
    "  mrs x11, tpidr_el0\n"
    "  eor x11, x11, x2\n"
    "  add x9, x9, x11\n"
    /* a page whose reading comes and goes, read directly and through x18 */
    "  ldr x12, [x3]\n"
    "  add x9, x9, x12\n"
    "  mov x18, x3\n"
    "  ldr x12, [x18, #8]\n"
    "  eor x9, x9, x12\n"
    /* calls: through a register (a lookup) and direct */
    "  adr x13, js_leaf\n"
    "  blr x13\n"
    "  bl js_leaf2\n"
    /* literal loads, adrp, a vector literal */
    "  ldr x14, 2f\n"
    "  add x9, x9, x14\n"
    "  adrp x15, 2f\n"
    "  add x15, x15, :lo12:2f\n"
    "  ldr x15, [x15]\n"
    "  eor x9, x9, x15\n"
    "  ldr q0, 2f\n"
    "  fmov x15, d0\n"
    "  add x9, x9, x15\n"
    /* x16 and x17 kept across the calls */
    "  add x9, x9, x16\n"
    "  eor x9, x9, x17\n"
    /* branches on x18 and on a bit */
    "  cbnz x18, 3f\n"
    "  add x9, x9, #1\n"
    "3: tbz x9, #0, 4f\n"
    "  add x9, x9, #7\n"
    /* now and then a system call (getpid) */
    "4: ands x10, x4, #63\n"
    "  b.ne 5f\n"
    "  mov x8, #172\n"
    "  svc #0\n"
    "  add x9, x9, x0\n"
    "5: subs x4, x4, #1\n"
    "  b.ne 1b\n"
    "  mov x0, x9\n"
    "  ldp x29, x30, [sp], #16\n"
    "  ret\n"

    "js_leaf:\n"
    "  add x9, x9, #5\n"
    "  eor x9, x9, x9, lsr #7\n"
    "  ret\n"
    "js_leaf2:\n"
    "  eor x9, x9, x9, lsl #3\n"
    "  add x9, x9, #11\n"
    "  ret\n"

    "  .balign 16\n"
    "2: .quad 0x123456789abcdef1, 0\n"
    /* written by the patcher: data in the code's page */
    "js_scratch:\n"
    "  .quad 0\n"

    ".globl js_end\n"
    "js_end:\n"
    ".balign 4096\n"
    ".text\n");

extern const char js_begin[], js_end[], js_work[], js_scratch[];

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

static char *code;
static long table[4] = {0x1111, 0x2222, 0x4444, 0x8888};
static long *poll;
static atomic_long signals, faults;
static atomic_int stop;

#define WORKERS 2
#define ROUNDS 20
#define N 5000

typedef long (*work_fn)(long, long *, long, long *);

static long run(void) {
    uint64_t tp;
    __asm__ volatile("mrs %0, tpidr_el0" : "=r"(tp));
    return ((work_fn)(code + (js_work - js_begin)))(N, table, (long)tp, poll);
}

static void on_usr1(int sig, void *si, void *ctx) {
    (void)sig;
    (void)si;
    (void)ctx;
    atomic_fetch_add(&signals, 1);
}

/* The poll page's reading taken away: given back, and the load retried. */
static void on_segv(int sig, void *si, void *ctx) {
    (void)sig;
    (void)ctx;
    if ((SI_ADDR(si) & ~4095ul) != (uint64_t)poll) {
        *(volatile int *)0 = 0;
    }
    atomic_fetch_add(&faults, 1);
    mprotect(poll, 4096, PROT_READ | PROT_WRITE);
}

static long reference;
static atomic_int right, done;
static unsigned long workers[WORKERS];

static void *worker(void *arg) {
    (void)arg;
    for (int r = 0; r < ROUNDS; r++) {
        if (run() == reference) {
            atomic_fetch_add(&right, 1);
        }
    }
    atomic_fetch_add(&done, 1);
    return 0;
}

static void *signaller(void *arg) {
    (void)arg;
    while (!atomic_load(&stop)) {
        for (int i = 0; i < WORKERS; i++) {
            pthread_kill(workers[i], SIGUSR1);
        }
        usleep(50);
    }
    return 0;
}

static void *poller(void *arg) {
    (void)arg;
    while (!atomic_load(&stop)) {
        mprotect(poll, 4096, PROT_NONE);
        usleep(100);
    }
    return 0;
}

static void *patcher(void *arg) {
    (void)arg;
    volatile long *scratch = (volatile long *)(code + (js_scratch - js_begin));
    while (!atomic_load(&stop)) {
        *scratch += 1;
        usleep(500);
    }
    return 0;
}

int main(void) {
    size_t len = (size_t)(js_end - js_begin);
    code = mmap(0, len, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memcpy(code, js_begin, len);
    flush(code, len);
    poll = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    poll[0] = 0x55;
    poll[1] = 0x66;

    struct sigaction usr1 = {0}, segv = {0};
    usr1.sa_sigaction = on_usr1;
    usr1.sa_flags = SA_SIGINFO | SA_RESTART;
    sigaction(SIGUSR1, &usr1, 0);
    segv.sa_sigaction = on_segv;
    segv.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &segv, 0);

    reference = run();

    for (int i = 0; i < WORKERS; i++) {
        pthread_create(&workers[i], 0, worker, 0);
    }
    unsigned long others[3];
    pthread_create(&others[0], 0, signaller, 0);
    pthread_create(&others[1], 0, poller, 0);
    pthread_create(&others[2], 0, patcher, 0);
    /* The storm stops before a worker is joined: joining frees the thread
     * the signaller names. */
    while (atomic_load(&done) < WORKERS) {
        usleep(1000);
    }
    atomic_store(&stop, 1);
    for (int i = 0; i < 3; i++) {
        pthread_join(others[i], 0);
    }
    for (int i = 0; i < WORKERS; i++) {
        pthread_join(workers[i], 0);
    }
    mprotect(poll, 4096, PROT_READ | PROT_WRITE);
    printf("storm: %d of %d rounds right\n", atomic_load(&right), WORKERS * ROUNDS);
    printf("storm: signals %s, faults %s\n", atomic_load(&signals) ? "landed" : "none",
           atomic_load(&faults) ? "landed" : "none");
    return 0;
}
