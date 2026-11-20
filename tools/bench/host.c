// What the host's work behind a translator costs, natively: a fault (a
// fetch from a writable page that is not executable, how native code's
// jump into a JIT's code reaches fwe, and a read of a page with no
// access, each caught by a handler that goes on past it), in
// microseconds; and making code ready to run after writing it, in
// nanoseconds a cache line: `dc cvau` alone, `ic ivau` alone (each line
// of a block of seven, with the barriers a block takes), and the system's
// `sys_icache_invalidate` of such a block.
#include <libkern/OSCacheControl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/ucontext.h>
#include <time.h>

static void on(int sig, siginfo_t *si, void *ctx) {
    ucontext_t *uc = ctx;
    (void)sig;
    // A fetch goes back to its caller; a read is skipped.
    if ((void *)uc->uc_mcontext->__ss.__pc == si->si_addr)
        uc->uc_mcontext->__ss.__pc = uc->uc_mcontext->__ss.__lr;
    else
        uc->uc_mcontext->__ss.__pc += 4;
}

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

enum { LINES = 7, BLOCK = 512, BLOCKS = 1 << 14 };

// Each of BLOCKS blocks written (LINES lines of `nop`), then made ready
// by `how`: 0 written alone, 1 `dc cvau`, 2 `ic ivau`, 3 the system's
// call. Nanoseconds a block.
static double ready(char *c, int how) {
    double t = now();
    for (int k = 0; k < BLOCKS; k++) {
        char *p = c + (size_t)k * BLOCK;
        pthread_jit_write_protect_np(0);
        for (int i = 0; i < LINES * 16; i++)
            ((unsigned *)p)[i] = 0xd503201f;
        pthread_jit_write_protect_np(1);
        if (how == 1 || how == 2) {
            for (int i = 0; how == 1 && i < LINES; i++)
                __asm__ volatile("dc cvau, %0" ::"r"(p + 64 * i));
            __asm__ volatile("dsb ish");
            for (int i = 0; how == 2 && i < LINES; i++)
                __asm__ volatile("ic ivau, %0" ::"r"(p + 64 * i));
            __asm__ volatile("dsb ish\nisb");
        } else if (how == 3) {
            sys_icache_invalidate(p, LINES * 64);
        }
    }
    return (now() - t) / BLOCKS * 1e9;
}

int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 20000;
    struct sigaction sa = {0};
    sa.sa_sigaction = on;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, 0);
    sigaction(SIGBUS, &sa, 0);
    unsigned *code = mmap(0, 16384, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    volatile int *none = mmap(0, 16384, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    char *jit = mmap(0, (size_t)BLOCKS * BLOCK, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANON | MAP_JIT, -1, 0);
    if (code == MAP_FAILED || none == MAP_FAILED || jit == MAP_FAILED)
        return 1;
    code[0] = 0xd65f03c0; // ret
    void (*f)(void) = (void (*)(void))code;
    double t = now();
    for (int i = 0; i < n; i++)
        f();
    double fetch = (now() - t) / n;
    t = now();
    for (int i = 0; i < n; i++)
        (void)*none;
    double read = (now() - t) / n;
    ready(jit, 0); // (The pages' first touch.)
    double written = ready(jit, 0);
    double dc = (ready(jit, 1) - written) / LINES;
    double ic = (ready(jit, 2) - written) / LINES;
    double sys = (ready(jit, 3) - written) / LINES;
    printf("%.2f %.2f %.1f %.1f %.1f\n", fetch * 1e6, read * 1e6, dc, ic, sys);
    return 0;
}
