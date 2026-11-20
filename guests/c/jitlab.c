/* What a JIT does with the code it writes, as a contract for any way of
 * running code made executable at run time. The code is assembled below
 * into a page-aligned template (data, in .rodata), copied into memory
 * mapped writable and executable, and run from there:
 *
 * - calls (bl) and returns, loops, conditional branches;
 * - indirect calls (blr) into static code that calls back into it;
 * - adr, adrp and a literal load, with data placed among the code,
 *   including a word that reads as an instruction naming x18;
 * - x18 kept across system calls (Linux lets code use it);
 * - a system call made from it;
 * - a blocking call from it interrupted by a signal whose handler has
 *   SA_RESTART: the handler sees the call's own address, and the call is
 *   made again;
 * - a signal from another thread landing while it runs: the handler sees
 *   an address in it;
 * - a tracer stopping a child at a system call made from it: the pc it
 *   reads is in the code;
 * - a load through a null pointer faulting at its own instruction, the
 *   handler sending it on to a continuation (a JIT's null check);
 * - a `brk` in it trapping at its own instruction, again and again, the
 *   handler stepping past it (a JIT's breakpoint or guard);
 * - code patched in place, then run;
 * - code copied elsewhere and run there;
 * - the return address a call leaves being the code's own address;
 * - x16 and x17 kept across a call into it and its return, as a call
 *   whose clobbers leave them out expects (HotSpot calls its atomic stubs
 *   so);
 * - threads running code while another thread patches it;
 * - threads running code while writing data in its page, at once, with
 *   plain stores, releases and compare-and-swap;
 * - code made executable with mprotect after it was written (W^X);
 * - code run, its memory given back (MADV_DONTNEED), written anew and run;
 * - a fork child running code translated before, and code it changes;
 * - and the memory reading back exactly as the program wrote it.
 *
 * Every line printed is what Linux prints. */
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

/* Declared here, so the guest builds with no libc headers on the host
 * (musl's layouts). */
int printf(const char *fmt, ...);
void perror(const char *s);
void *memcpy(void *d, const void *s, size_t n);
int memcmp(const void *a, const void *b, size_t n);
void *mmap(void *addr, size_t len, int prot, int flags, int fd, long off);
int mprotect(void *addr, size_t len, int prot);
int madvise(void *addr, size_t len, int advice);
int getpid(void);
int pthread_create(unsigned long *t, const void *attr, void *(*fn)(void *), void *arg);
int pthread_join(unsigned long t, void **ret);
struct sigaction {
    void (*sa_sigaction)(int, void *, void *);
    unsigned long sa_mask[16];
    int sa_flags;
    void (*sa_restorer)(void);
};
int sigaction(int sig, const struct sigaction *act, struct sigaction *old);
int fork(void);
int pipe(int fd[2]);
long write(int fd, const void *buf, size_t n);
long read(int fd, void *buf, size_t n);
int memfd_create(const char *name, unsigned flags);
int ftruncate(int fd, long len);
int munmap(void *addr, size_t len);
int pthread_kill(unsigned long t, int sig);
unsigned long pthread_self(void);
int usleep(unsigned us);
long ptrace(int req, int pid, void *addr, void *data);
int kill(int pid, int sig);
struct iovec {
    void *base;
    size_t len;
};
int waitpid(int pid, int *status, int options);
void _exit(int code);
#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#define MAP_SHARED 1
#define MAP_FIXED 0x10
#define PROT_NONE 0
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20
#define MAP_FAILED ((void *)-1)
#define SIGTRAP 5
#define SIGSEGV 11
#define SA_SIGINFO 4
#define SA_RESTART 0x10000000
#define SIGUSR1 10
#define SIGUSR2 12
#define SIGSTOP 19
#define PTRACE_TRACEME 0
#define PTRACE_CONT 7
#define PTRACE_SYSCALL 24
#define PTRACE_GETREGSET 0x4204
#define NT_PRSTATUS 1
/* The interrupted pc in an arm64 signal frame's ucontext. */
#define UC_PC(ctx) (*(uint64_t *)((char *)(ctx) + 440))
/* si_addr in a siginfo. */
#define SI_ADDR(si) (*(uint64_t *)((char *)(si) + 16))

__asm__(
    ".section .rodata\n"
    ".balign 4096\n"
    ".globl jl_begin\n"
    "jl_begin:\n"

    /* long sum(long n): the sum of double(i) for i < n, double called. */
    "jl_sum:\n"
    "  stp x29, x30, [sp, #-32]!\n"
    "  mov x29, sp\n"
    "  stp x19, x20, [sp, #16]\n"
    "  mov x19, x0\n"
    "  mov x20, #0\n"
    "1: cbz x19, 2f\n"
    "  sub x19, x19, #1\n"
    "  mov x0, x19\n"
    "  bl jl_double\n"
    "  add x20, x20, x0\n"
    "  b 1b\n"
    "2: mov x0, x20\n"
    "  ldp x19, x20, [sp, #16]\n"
    "  ldp x29, x30, [sp], #32\n"
    "  ret\n"
    "jl_double:\n"
    "  lsl x0, x0, #1\n"
    "  ret\n"

    /* long indirect(long (*f)(long, long), long a, long b):
     * f(f(a, b), double(3)), double reached through a register. */
    "jl_indirect:\n"
    "  stp x29, x30, [sp, #-32]!\n"
    "  mov x29, sp\n"
    "  str x19, [sp, #16]\n"
    "  mov x19, x0\n"
    "  mov x0, x1\n"
    "  mov x1, x2\n"
    "  blr x19\n"
    "  str x0, [sp, #24]\n"
    "  mov x0, #3\n"
    "  adr x9, jl_double\n"
    "  blr x9\n"
    "  mov x1, x0\n"
    "  ldr x0, [sp, #24]\n"
    "  blr x19\n"
    "  ldr x19, [sp, #16]\n"
    "  ldp x29, x30, [sp], #32\n"
    "  ret\n"

    /* long pcrel(void): 0x1111 + 0x2222 + 0x4444, by adr, a literal load
     * and adrp. */
    "jl_pcrel:\n"
    "  adr x0, 3f\n"
    "  ldr x0, [x0]\n"
    "  ldr x1, 4f\n"
    "  add x0, x0, x1\n"
    "  adrp x2, 5f\n"
    "  add x2, x2, :lo12:5f\n"
    "  ldr x2, [x2]\n"
    "  add x0, x0, x2\n"
    "  ret\n"
    "  .balign 8\n"
    "3: .quad 0x1111\n"
    "4: .quad 0x2222\n"
    "5: .quad 0x4444\n"
    /* Data among the code that reads as `ldr x0, [x18, #8]`. */
    "  .word 0xf9400640, 0x00000200\n"

    /* long x18(long v, long rounds): x18 = v across `rounds` system calls. */
    "jl_x18:\n"
    "  mov x18, x0\n"
    "  mov x9, x1\n"
    "6: cbz x9, 7f\n"
    "  mov x8, #124\n" /* sched_yield */
    "  svc #0\n"
    "  sub x9, x9, #1\n"
    "  b 6b\n"
    "7: mov x0, x18\n"
    "  ret\n"

    /* long read_jit(int fd, void *buf, long n) */
    "jl_read:\n"
    "  mov x8, #63\n"
    "jl_read_svc:\n"
    "  svc #0\n"
    "  ret\n"

    /* void spin(int *flag): until *flag is set. */
    "jl_spin:\n"
    "8: ldr w1, [x0]\n"
    "  cbz w1, 8b\n"
    "  ret\n"

    /* long via_x30(long (*f)(long), long v): f(v), called through x30. */
    "jl_via_x30:\n"
    "  stp x29, x30, [sp, #-16]!\n"
    "  mov x2, x0\n"
    "  mov x0, x1\n"
    "  mov x30, x2\n"
    "  blr x30\n"
    "  ldp x29, x30, [sp], #16\n"
    "  ret\n"

    /* long getpid_jit(void) */
    "jl_getpid:\n"
    "  mov x8, #172\n"
    "  svc #0\n"
    "  ret\n"

    /* long fault(long *p): a load through p, by way of x18. */
    "jl_fault:\n"
    "  mov x18, x0\n"
    "jl_fault_load:\n"
    "  ldr x0, [x18, #16]\n"
    "  ret\n"
    "jl_fault_cont:\n"
    "  mov x0, #77\n"
    "  ret\n"

    /* long trap(long v): v + 1, past a `brk` between. */
    "jl_trap:\n"
    "  mov x0, x0\n"
    "jl_trap_brk:\n"
    "  brk #7\n"
    "  add x0, x0, #1\n"
    "  ret\n"

    /* long ret1(void): patched to return other numbers. */
    "jl_ret1:\n"
    "  mov x0, #1\n"
    "  ret\n"

    /* long retaddr(void): the return address its call left. */
    "jl_retaddr_callee:\n"
    "  mov x0, x30\n"
    "  ret\n"
    "jl_retaddr:\n"
    "  stp x29, x30, [sp, #-16]!\n"
    "  bl jl_retaddr_callee\n"
    "jl_retaddr_after:\n"
    "  ldp x29, x30, [sp], #16\n"
    "  ret\n"

    /* Data the writers below keep beside the code, one word each. */
    "  .balign 64\n"
    "jl_slots:\n"
    "  .fill 8, 8, 0\n"

    ".globl jl_end\n"
    "jl_end:\n"
    ".balign 4096\n"
    ".text\n");

extern const char jl_begin[], jl_end[], jl_sum[], jl_indirect[], jl_pcrel[], jl_x18[],
    jl_getpid[], jl_fault[], jl_fault_load[], jl_fault_cont[], jl_trap[], jl_trap_brk[], jl_ret1[],
    jl_retaddr[],
    jl_retaddr_after[], jl_slots[], jl_read[], jl_read_svc[], jl_spin[], jl_via_x30[];

static size_t template_len(void) { return (size_t)(jl_end - jl_begin); }

/* The address of template symbol `sym` in a copy at `base`. */
static void *at(char *base, const char *sym) { return base + (sym - jl_begin); }

/* Make code just written visible to instruction fetch, as Linux's
 * __clear_cache does: clean the data cache to the point of unification,
 * invalidate the instruction cache, by the lines CTR_EL0 gives. */
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

static long host_add(long a, long b) { return a + b; }
static long host_twice(long v) { return 2 * v; }

static char *code;
static atomic_int fault_seen;

static void on_segv(int sig, void *si, void *ctx) {
    (void)sig;
    (void)si;
    if (UC_PC(ctx) == (uint64_t)at(code, jl_fault_load)) {
        atomic_store(&fault_seen, 1);
    }
    UC_PC(ctx) = (uint64_t)at(code, jl_fault_cont);
}

static int traps_at_brk;

/* A `brk`: seen at its instruction (pc and si_addr), and stepped past. */
static void on_trap(int sig, void *si, void *ctx) {
    (void)sig;
    uint64_t brk = (uint64_t)at(code, jl_trap_brk);
    traps_at_brk += UC_PC(ctx) == brk && SI_ADDR(si) == brk;
    UC_PC(ctx) += 4;
}

static atomic_uint_least64_t usr1_pc;

static void on_usr1(int sig, void *si, void *ctx) {
    (void)sig;
    (void)si;
    atomic_store(&usr1_pc, UC_PC(ctx));
}

/* The main thread, which the signals below interrupt. */
static unsigned long restart_reader;

static atomic_int spin_flag;
static atomic_uint_least64_t usr2_pc;

static void on_usr2(int sig, void *si, void *ctx) {
    (void)sig;
    (void)si;
    atomic_store(&usr2_pc, UC_PC(ctx));
    atomic_store(&spin_flag, 1);
}

/* Lands a signal on the spinning thread. */
static void *nudger(void *arg) {
    (void)arg;
    usleep(50000);
    pthread_kill(restart_reader, SIGUSR2);
    return 0;
}

static int restart_pipe[2];

/* Interrupts the reader's call, then gives it something to read. */
static void *interrupter(void *arg) {
    (void)arg;
    usleep(100000);
    pthread_kill(restart_reader, SIGUSR1);
    usleep(100000);
    write(restart_pipe[1], "j", 1);
    return 0;
}

static atomic_int stop;
static atomic_long bad;

static void *runner(void *arg) {
    long (*ret1)(void) = (long (*)(void))at(code, jl_ret1);
    long (*sum)(long) = (long (*)(long))at(code, jl_sum);
    (void)arg;
    while (!atomic_load(&stop)) {
        long r = ret1();
        if (r != 1 && r != 2) {
            atomic_fetch_add(&bad, 1);
        }
        if (sum(10) != 90) {
            atomic_fetch_add(&bad, 1);
        }
    }
    return 0;
}

#define WRITERS 4
#define WRITES 2000

static void store_release(volatile long *p, long v) {
    __asm__ volatile("stlr %1, [%0]" ::"r"(p), "r"(v) : "memory");
}

/* Add 1 to `*p` with compare-and-swap (LSE's `casal`, as a JIT's atomics). */
static void cas_increment(volatile long *p) {
    long old = *p;
    for (;;) {
        long seen = old;
        __asm__ volatile(".arch_extension lse\n"
                         "casal %0, %2, [%1]"
                         : "+r"(seen)
                         : "r"(p), "r"(old + 1)
                         : "memory");
        if (seen == old) {
            return;
        }
        old = seen;
    }
}

/* Runs the code, then writes its own word in the code's page (plainly
 * and as a release, by turns) and adds 1 to a word they share there: the
 * writers write the page at once, each write after code there ran. */
static void *writer(void *arg) {
    long i = (long)arg;
    long (*sum)(long) = (long (*)(long))at(code, jl_sum);
    volatile long *slot = (volatile long *)at(code, jl_slots) + i;
    volatile long *shared = (volatile long *)at(code, jl_slots) + 7;
    for (long k = 1; k <= WRITES; k++) {
        if (sum(10) != 90) {
            atomic_fetch_add(&bad, 1);
        }
        if (k & 1) {
            *slot = k;
        } else {
            store_release(slot, k);
        }
        if (*slot != k) {
            atomic_fetch_add(&bad, 1);
        }
        cas_increment(shared);
    }
    return 0;
}

/* Calls into code that say they clobber only x8, x9 and x30, as HotSpot
 * calls its generated atomic stubs: x16 and x17 are kept live across
 * them. The code (`mov x0, #1; ret`) is fresh, and called many times, so
 * its returns take every way fwe has. In how many calls they changed. */
static int fastcalls_changing(void) {
    static const uint32_t ret1_words[] = {0xd2800020, 0xd65f03c0};
    uint32_t *fn = mmap(0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memcpy(fn, ret1_words, sizeof ret1_words);
    flush(fn, sizeof ret1_words);
    int changed = 0;
    for (int i = 0; i < 1000; i++) {
        register uint64_t r16 __asm__("x16") = 0x1616161616161616ull + (uint64_t)i;
        register uint64_t r17 __asm__("x17") = 0x1717171717171717ull + (uint64_t)i;
        register uint64_t r0 __asm__("x0") = 0;
        register void *f __asm__("x3") = fn;
        __asm__ volatile("blr %[f]"
                         : "+r"(r0), "+r"(r16), "+r"(r17)
                         : [f] "r"(f)
                         : "x8", "x9", "x30", "cc", "memory");
        changed += r16 != 0x1616161616161616ull + (uint64_t)i ||
                   r17 != 0x1717171717171717ull + (uint64_t)i;
    }
    return changed;
}

static uint32_t movz_x0(unsigned imm) { return 0xd2800000u | (imm << 5); }

int main(void) {
    /* Memory asked for at 32 TiB first, as a JVM may place its heap or
     * class space, before any code is made: where fwe keeps its table of
     * translations (which takes its place before the program runs), so
     * this goes elsewhere; Linux would place it there. Nothing printed
     * depends on where. */
    mmap((void *)(1ul << 45), 1 << 20, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    size_t len = template_len();
    code = mmap(0, len, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    /* What the program's memory must read back as. */
    static char expect[1 << 16];
    memcpy(code, jl_begin, len);
    memcpy(expect, jl_begin, len);
    flush(code, len);

    long (*sum)(long) = (long (*)(long))at(code, jl_sum);
    printf("calls: %ld\n", sum(10));

    long (*indirect)(long (*)(long, long), long, long) =
        (long (*)(long (*)(long, long), long, long))at(code, jl_indirect);
    printf("indirect: %ld\n", indirect(host_add, 5, 10));

    long (*via_x30)(long (*)(long), long) = (long (*)(long (*)(long), long))at(code, jl_via_x30);
    long x30_sum = 0;
    for (long i = 0; i < 100; i++) {
        x30_sum += via_x30(host_twice, i);
    }
    printf("call through x30: %ld\n", x30_sum);

    long (*pcrel)(void) = (long (*)(void))at(code, jl_pcrel);
    printf("pcrel: %ld\n", pcrel());

    long (*x18)(long, long) = (long (*)(long, long))at(code, jl_x18);
    printf("x18: %s\n", x18(0x1818abcd, 2000) == 0x1818abcd ? "kept" : "lost");

    long (*getpid_jit)(void) = (long (*)(void))at(code, jl_getpid);
    printf("getpid: %s\n", getpid_jit() == getpid() ? "matches" : "differs");

    struct sigaction usr1 = {0};
    usr1.sa_sigaction = on_usr1;
    usr1.sa_flags = SA_SIGINFO | SA_RESTART;
    sigaction(SIGUSR1, &usr1, 0);
    pipe(restart_pipe);
    restart_reader = pthread_self();
    unsigned long irq;
    pthread_create(&irq, 0, interrupter, 0);
    char got = 0;
    long n = ((long (*)(int, void *, long))at(code, jl_read))(restart_pipe[0], &got, 1);
    pthread_join(irq, 0);
    uint64_t seen = atomic_load(&usr1_pc);
    printf("restart: %ld %c, the handler saw %s\n", n, got,
           seen == (uint64_t)at(code, jl_read_svc)       ? "the call"
           : seen == (uint64_t)at(code, jl_read_svc) + 4 ? "past the call"
                                                         : "elsewhere");

    struct sigaction usr2 = {0};
    usr2.sa_sigaction = on_usr2;
    usr2.sa_flags = SA_SIGINFO;
    sigaction(SIGUSR2, &usr2, 0);
    pthread_create(&irq, 0, nudger, 0);
    ((void (*)(atomic_int *))at(code, jl_spin))(&spin_flag);
    pthread_join(irq, 0);
    uint64_t spun = atomic_load(&usr2_pc);
    printf("signal: seen %s\n",
           spun >= (uint64_t)at(code, jl_spin) && spun < (uint64_t)at(code, jl_spin) + 12
               ? "in the code"
               : "elsewhere");

    /* A tracer reads the pc of a child's call made from the code. */
    int traced = fork();
    if (traced == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        kill(getpid(), SIGSTOP);
        getpid_jit();
        _exit(0);
    }
    int st = 0;
    waitpid(traced, &st, 0);
    uint64_t stop_pc = 0;
    for (int i = 0; i < 16 && stop_pc == 0; i++) {
        ptrace(PTRACE_SYSCALL, traced, 0, 0);
        if (waitpid(traced, &st, 0) != traced || (st & 0x7f) == 0) {
            break;
        }
        uint64_t ur[34];
        struct iovec iov = {ur, sizeof ur};
        if (ptrace(PTRACE_GETREGSET, traced, (void *)NT_PRSTATUS, &iov) == 0 && ur[8] == 172) {
            stop_pc = ur[32];
        }
    }
    ptrace(PTRACE_CONT, traced, 0, 0);
    waitpid(traced, &st, 0);
    printf("tracer: pc %s\n",
           stop_pc >= (uint64_t)at(code, jl_getpid) && stop_pc < (uint64_t)at(code, jl_getpid) + 12
               ? "in the code"
               : "elsewhere");

    struct sigaction sa = {0};
    sa.sa_sigaction = on_segv;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, 0);
    long (*fault)(long *) = (long (*)(long *))at(code, jl_fault);
    long r = fault(0);
    printf("fault: %s, %ld\n", atomic_load(&fault_seen) ? "seen at the load" : "seen elsewhere", r);

    sa.sa_sigaction = on_trap;
    sigaction(SIGTRAP, &sa, 0);
    long (*trap)(long) = (long (*)(long))at(code, jl_trap);
    long sum_traps = 0;
    for (long i = 0; i < 1000; i++) {
        sum_traps += trap(i);
    }
    printf("brk: at its instruction %d of 1000, %ld\n", traps_at_brk, sum_traps);

    long (*ret1)(void) = (long (*)(void))at(code, jl_ret1);
    int patched = 0;
    for (unsigned i = 0; i < 1000; i++) {
        uint32_t w = movz_x0(i % 7);
        memcpy(at(code, jl_ret1), &w, 4);
        memcpy(at(expect, jl_ret1), &w, 4);
        flush(at(code, jl_ret1), 4);
        patched += ret1() == (long)(i % 7);
    }
    printf("patch: %d of 1000\n", patched);

    /* A copy elsewhere, at the same offset in its page (adrp is relative to
     * the page). */
    char *copy = mmap(0, len, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memcpy(copy, code, len);
    static char copy_expect[1 << 16];
    memcpy(copy_expect, copy, len);
    flush(copy, len);
    printf("copy: %ld %ld\n", ((long (*)(long))at(copy, jl_sum))(10),
           ((long (*)(void))at(copy, jl_pcrel))());

    printf("x16 and x17 across a call: changed in %d of 1000\n", fastcalls_changing());

    long (*retaddr)(void) = (long (*)(void))at(code, jl_retaddr);
    printf("return address: %s\n",
           retaddr() == (long)at(code, jl_retaddr_after) ? "the code's own" : "elsewhere");

    /* Threads run while this one patches, between returning 1 and 2. */
    uint32_t one = movz_x0(1), two = movz_x0(2);
    memcpy(at(code, jl_ret1), &one, 4);
    flush(at(code, jl_ret1), 4);
    unsigned long t[4];
    for (int i = 0; i < 4; i++) {
        pthread_create(&t[i], 0, runner, 0);
    }
    for (int i = 0; i < 20000; i++) {
        memcpy(at(code, jl_ret1), (i & 1) ? &one : &two, 4);
        flush(at(code, jl_ret1), 4);
    }
    atomic_store(&stop, 1);
    for (int i = 0; i < 4; i++) {
        pthread_join(t[i], 0);
    }
    memcpy(at(expect, jl_ret1), &one, 4);
    printf("threads: %s\n", atomic_load(&bad) ? "wrong results" : "ok");

    /* Any fault now is one the writers should not take. */
    sa.sa_sigaction = 0;
    sa.sa_flags = 0;
    sigaction(SIGSEGV, &sa, 0);
    for (long i = 0; i < WRITERS; i++) {
        pthread_create(&t[i], 0, writer, (void *)i);
    }
    for (int i = 0; i < WRITERS; i++) {
        pthread_join(t[i], 0);
    }
    for (int i = 0; i < WRITERS; i++) {
        long last = WRITES;
        memcpy((long *)at(expect, jl_slots) + i, &last, sizeof last);
    }
    long total = WRITERS * WRITES;
    if (*((volatile long *)at(code, jl_slots) + 7) != total) {
        atomic_fetch_add(&bad, 1);
    }
    memcpy((long *)at(expect, jl_slots) + 7, &total, sizeof total);
    printf("writers: %s\n", atomic_load(&bad) ? "wrong results" : "ok");

    /* Written, then made executable (and back), as a W^X JIT does. */
    char *wx = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memcpy(wx, jl_begin, len);
    static char wx_expect[1 << 16];
    memcpy(wx_expect, jl_begin, len);
    mprotect(wx, len, PROT_READ | PROT_EXEC);
    long first = ((long (*)(long))at(wx, jl_sum))(10);
    mprotect(wx, len, PROT_READ | PROT_WRITE);
    memcpy(at(wx, jl_ret1), &two, 4);
    memcpy(at(wx_expect, jl_ret1), &two, 4);
    mprotect(wx, len, PROT_READ | PROT_EXEC);
    printf("w^x: %ld %ld\n", first, ((long (*)(void))at(wx, jl_ret1))());

    /* A read into the page of code that ran: Linux writes it as the
     * program's own store would. */
    uint32_t *page = mmap(0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS,
                          -1, 0);
    page[0] = movz_x0(5);
    page[1] = 0xd65f03c0; /* ret */
    flush(page, 8);
    long ran = ((long (*)(void))page)();
    int fds[2];
    pipe(fds);
    write(fds[1], "hello", 6);
    long nread = read(fds[0], (char *)page + 64, 6);
    printf("read into code's page: %ld %ld %s, then %ld\n", ran, nread, (char *)page + 64,
           ((long (*)(void))page)());

    /* Code mapped twice through a memfd, as a W^X JIT keeps it: written
     * through the writable view, run through the executable one, the
     * writable view replaced by a new one after the code ran. */
    int mfd = memfd_create("jit", 0);
    ftruncate(mfd, 16384);
    uint32_t *rw = mmap(0, 16384, PROT_READ | PROT_WRITE, MAP_SHARED, mfd, 0);
    uint32_t *rx = mmap(0, 16384, PROT_READ | PROT_EXEC, MAP_SHARED, mfd, 0);
    long (*view)(void) = (long (*)(void))rx;
    rw[0] = movz_x0(1);
    rw[1] = 0xd65f03c0; /* ret */
    flush(rx, 8);
    long v1 = view();
    rw[0] = movz_x0(2);
    flush(rw, 4); /* through the view written: the same memory */
    long v2 = view();
    munmap(rw, 16384);
    rw = mmap(0, 16384, PROT_READ | PROT_WRITE, MAP_SHARED, mfd, 0);
    rw[0] = movz_x0(3);
    flush(rx, 4);
    printf("two views: %ld %ld %ld\n", v1, v2, view());

    /* A file's code mapped private, writable and executable: it runs, and
     * reads back as the file holds it. */
    static const uint32_t getpid_code[] = {
        0xd2801588, /* mov x8, #172 (getpid) */
        0xd4000001, /* svc #0 */
        0xd65f03c0, /* ret */
    };
    int cfd = memfd_create("code", 0);
    write(cfd, getpid_code, sizeof getpid_code);
    ftruncate(cfd, 16384);
    uint32_t *fc = mmap(0, 16384, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, cfd, 0);
    long fpid = ((long (*)(void))fc)();
    printf("file code: getpid %s, memory %s\n", fpid == getpid() ? "matches" : "differs",
           memcmp(fc, getpid_code, sizeof getpid_code) == 0 ? "as written" : "changed");

    /* Calls with `bl` from code made at run time to code of a file (code
     * mapped private and not writable, which fwe does not translate) in
     * reach of it, as a JIT calls its
     * runtime's helpers: each returns into the code. */
    {
        static const uint32_t twice[] = {
            0x8b000000, /* add x0, x0, x0 */
            0xd65f03c0, /* ret */
        };
        int rfd = memfd_create("twice", 0);
        write(rfd, twice, sizeof twice);
        ftruncate(rfd, 16384);
        char *both = mmap(0, 2 * 16384, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        mmap(both, 16384, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_FIXED, rfd, 0);
        uint32_t *bl = mmap(both + 16384, 16384, PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        /* long f(long n): x19 = n; x20 = 0; do x20 += twice(x19) while --x19 */
        uint32_t words[] = {
            0xa9be7bfd, /* stp x29, x30, [sp, #-32]! */
            0xa90153f3, /* stp x19, x20, [sp, #16] */
            0xaa0003f3, /* mov x19, x0 */
            0xd2800014, /* mov x20, #0 */
            0xaa1303e0, /* 1: mov x0, x19 */
            0x94000000, /* bl twice (filled in) */
            0x8b000294, /* add x20, x20, x0 */
            0xf1000673, /* subs x19, x19, #1 */
            0x54ffff81, /* b.ne 1b */
            0xaa1403e0, /* mov x0, x20 */
            0xa94153f3, /* ldp x19, x20, [sp, #16] */
            0xa8c27bfd, /* ldp x29, x30, [sp], #32 */
            0xd65f03c0, /* ret */
        };
        long off = ((long)both - (long)&bl[5]) / 4;
        words[5] |= (uint32_t)off & 0x3ffffff;
        memcpy(bl, words, sizeof words);
        flush(bl, sizeof words);
        printf("bl out: %ld\n", ((long (*)(long))bl)(1000));
    }

    /* Called with `blr` from the program's own code, `x16` and `x17` set
     * for the callee to read: each call hands them over as they were,
     * the first (which fwe sees) and every one after. */
    {
        uint32_t *rd = mmap(0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        rd[0] = 0x8b110200; /* add x0, x16, x17 */
        rd[1] = 0xd65f03c0; /* ret */
        flush(rd, 8);
        int same = 0;
        for (int i = 0; i < 1000; i++) {
            register long x0 __asm__("x0");
            register long a __asm__("x16") = 0x1600 + i;
            register long b __asm__("x17") = 0x1700;
            register void *f __asm__("x9") = rd;
            __asm__ volatile("blr %3" : "=r"(x0), "+r"(a), "+r"(b) : "r"(f) : "x30", "memory");
            same += x0 == 0x2d00 + i && a == 0x1600 + i && b == 0x1700;
        }
        printf("x16 and x17 into the code: %d of 1000\n", same);
    }

    /* Made executable only (no PROT_READ), as Linux runs it. */
    uint32_t *xo = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    xo[0] = movz_x0(4);
    xo[1] = 0xd65f03c0; /* ret */
    flush(xo, 8);
    mprotect(xo, 4096, PROT_EXEC);
    printf("execute only: %ld\n", ((long (*)(void))xo)());

    /* Run, data written beside it, given back with MADV_DONTNEED (zeros
     * from now on, as Linux gives them), then written anew and run: the
     * new code runs. */
    volatile uint32_t *dn =
        mmap(0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    dn[0] = movz_x0(7);
    dn[1] = 0xd65f03c0; /* ret */
    flush((void *)dn, 8);
    long dn_ran = ((long (*)(void))dn)();
    dn[2] = 1; /* data beside it, written after it ran */
    madvise((void *)dn, 4096, 4 /* MADV_DONTNEED */);
    uint32_t zero = dn[0];
    dn[0] = movz_x0(9);
    dn[1] = 0xd65f03c0;
    flush((void *)dn, 8);
    printf("discarded: %ld, then %u, then %ld\n", dn_ran, zero, ((long (*)(void))dn)());

    int same = memcmp(code, expect, len) == 0 && memcmp(copy, copy_expect, len) == 0 &&
               memcmp(wx, wx_expect, len) == 0;
    printf("memory: %s\n", same ? "as written" : "changed");

    /* A child runs what ran before the fork, and code it changes. */
    int pid = fork();
    if (pid == 0) {
        uint32_t three = movz_x0(3);
        long before = sum(10);
        memcpy(at(code, jl_ret1), &three, 4);
        flush(at(code, jl_ret1), 4);
        _exit(before == 90 && ret1() == 3 ? 7 : 1);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    printf("fork: child %s, parent %ld\n", (status >> 8) == 7 ? "ok" : "wrong", ret1());
    return 0;
}
