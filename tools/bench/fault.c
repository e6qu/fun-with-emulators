// What a fault costs on the host, natively: a fetch from a writable page
// that is not executable (how native code's jump into a JIT's code reaches
// fwe) and a read of a page with no access, each caught by a handler that
// goes on past it. Prints the time each takes, in microseconds.
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

int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 20000;
    struct sigaction sa = {0};
    sa.sa_sigaction = on;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, 0);
    sigaction(SIGBUS, &sa, 0);
    unsigned *code = mmap(0, 16384, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    volatile int *none = mmap(0, 16384, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (code == MAP_FAILED || none == MAP_FAILED)
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
    printf("%.2f %.2f\n", fetch * 1e6, read * 1e6);
    return 0;
}
