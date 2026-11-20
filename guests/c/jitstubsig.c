/* Calls into code made at run time from the program's own code with x16
 * and x17 set (fwe links the call site to the code's translation through
 * a stub of its own), while another thread signals the caller over and
 * over and the handler calls code made at run time too, which sets x16
 * and x17 to values of its own. A signal that lands in the middle of a
 * call must not let the handler's values into the call it interrupted:
 * every call must see the x16 and x17 its caller set. (Once a signal
 * lands in the code made at run time, the caller goes on by translation
 * and its calls no longer go through the stub: each round is a program
 * of its own, started afresh by execve.) Every line printed is what Linux
 * prints. */
#include <stdint.h>
int printf(const char *fmt, ...);
void *mmap(void *addr, unsigned long len, int prot, int flags, int fd, long off);
int pthread_create(unsigned long *t, const void *attr, void *(*fn)(void *), void *arg);
int pthread_join(unsigned long t, void **ret);
unsigned long pthread_self(void);
int pthread_kill(unsigned long t, int sig);
int nanosleep(const void *req, void *rem);
int execve(const char *path, char *const argv[], char *const envp[]);

/* musl's struct sigaction. */
struct sigaction {
    void (*sa_handler)(int);
    unsigned long sa_mask[16];
    int sa_flags;
    void (*sa_restorer)(void);
};
int sigaction(int sig, const struct sigaction *act, struct sigaction *old);

#define SIGUSR1 10
#define CALLS 1000000
#define SIGNALS 200
#define ROUNDS 6

static uint32_t *code;
static unsigned long caller;
static volatile int done;
static volatile long handled;

/* x16 ^ x17, through code made at run time (at `code`). */
static long call(long a, long b) {
    register long x16 __asm__("x16") = a;
    register long x17 __asm__("x17") = b;
    register long x0 __asm__("x0");
    register void *f __asm__("x9") = code;
    __asm__ volatile("blr %3" : "=r"(x0), "+r"(x16), "+r"(x17) : "r"(f) : "x30", "memory");
    return x0;
}

static void on_signal(int sig) {
    (void)sig;
    /* Sets x16 and x17 to its own values and returns. */
    void (*g)(void) = (void (*)(void))(code + 8);
    g();
    handled++;
}

static void *signaller(void *arg) {
    (void)arg;
    struct {
        long s, ns;
    } pause = {0, 20000};
    while (!done) {
        pthread_kill(caller, SIGUSR1);
        nanosleep(&pause, 0);
    }
    return 0;
}

int main(int argc, char **argv) {
    int round = argc;
    code = mmap(0, 16384, 7, 0x22, -1, 0);
    code[0] = 0xca110200; /* eor x0, x16, x17 */
    code[1] = 0xd65f03c0; /* ret */
    code[8] = 0xd28b4b50; /* mov x16, #0x5a5a */
    code[9] = 0xd294b4b1; /* mov x17, #0xa5a5 */
    code[10] = 0xd65f03c0; /* ret */
    for (int k = 0; k < 64; k += 4) {
        __asm__ volatile("dc cvau, %0" ::"r"((char *)code + k));
        __asm__ volatile("ic ivau, %0" ::"r"((char *)code + k));
    }
    __asm__ volatile("dsb ish");
    __asm__ volatile("isb");
    struct sigaction sa = {0};
    sa.sa_handler = on_signal;
    sa.sa_flags = 0x10000000; /* SA_RESTART */
    sigaction(SIGUSR1, &sa, 0);
    caller = pthread_self();
    unsigned long t;
    pthread_create(&t, 0, signaller, 0);
    long bad = 0;
    /* At least so many calls, and on until so many signals came. */
    for (long i = 0; i < CALLS || handled < SIGNALS; i++) {
        long a = i * 0x10001, b = ~i;
        if (call(a, b) != (a ^ b)) {
            bad++;
        }
    }
    done = 1;
    pthread_join(t, 0);
    printf("round %d: wrong calls: %ld\n", round, bad);
    if (round < ROUNDS) {
        char *next[ROUNDS + 2];
        for (int k = 0; k <= round; k++) {
            next[k] = argv[0];
        }
        next[round + 1] = 0;
        execve("/proc/self/exe", next, 0);
        printf("execve failed\n");
        return 1;
    }
    return 0;
}
