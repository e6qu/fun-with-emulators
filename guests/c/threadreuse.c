/* A thread that starts after another ended starts as a new thread, with
 * nothing of the one before: fwe may run it on the host thread the ended
 * one left. The first thread of each round sets up a signal stack, a name,
 * a blocked signal and a rounding mode, then ends; the second, made by the
 * main thread once the first is joined, prints what it has: no signal
 * stack, its creator's name, mask and rounding mode.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

typedef unsigned long size_t;
typedef unsigned long pthread_t;
typedef struct {
    void *ss_sp;
    int ss_flags;
    size_t ss_size;
} stack_t;
typedef struct {
    unsigned long bits[16];
} sigset_t;

int pthread_create(pthread_t *thread, const void *attr, void *(*start)(void *), void *arg);
int pthread_join(pthread_t thread, void **ret);
int pthread_sigmask(int how, const sigset_t *set, sigset_t *old);
int sigemptyset(sigset_t *set);
int sigaddset(sigset_t *set, int sig);
int sigismember(const sigset_t *set, int sig);
int sigaltstack(const stack_t *ss, stack_t *old);
int prctl(int option, ...);
int printf(const char *format, ...);

#define SIG_BLOCK 0
#define SIGUSR1 10
#define SS_DISABLE 2
#define PR_SET_NAME 15
#define PR_GET_NAME 16
#define ROUNDS 4

static char altstack[16384];

static unsigned long fpcr(void) {
    unsigned long v;
    __asm__ volatile("mrs %0, fpcr" : "=r"(v));
    return v;
}

static void set_fpcr(unsigned long v) {
    __asm__ volatile("msr fpcr, %0" : : "r"(v));
}

static void *first(void *arg) {
    (void)arg;
    stack_t ss = {altstack, 0, sizeof altstack};
    sigaltstack(&ss, 0);
    prctl(PR_SET_NAME, "first");
    sigset_t s;
    sigemptyset(&s);
    sigaddset(&s, SIGUSR1);
    pthread_sigmask(SIG_BLOCK, &s, 0);
    /* Round towards plus infinity. */
    set_fpcr(1ul << 22);
    return 0;
}

static void *second(void *arg) {
    (void)arg;
    stack_t old;
    sigaltstack(0, &old);
    char name[16] = {0};
    prctl(PR_GET_NAME, name);
    sigset_t s;
    pthread_sigmask(SIG_BLOCK, 0, &s);
    printf("signal stack disabled: %d, name: %s, SIGUSR1 blocked: %d, rounding: %lu\n",
           (old.ss_flags & SS_DISABLE) != 0, name, sigismember(&s, SIGUSR1),
           (fpcr() >> 22) & 3);
    return 0;
}

int main(void) {
    prctl(PR_SET_NAME, "maker");
    /* Round towards zero, for the second threads to start with. */
    set_fpcr(3ul << 22);
    for (int i = 0; i < ROUNDS; i++) {
        pthread_t t;
        if (pthread_create(&t, 0, first, 0) != 0 || pthread_join(t, 0) != 0) {
            return 1;
        }
        if (pthread_create(&t, 0, second, 0) != 0 || pthread_join(t, 0) != 0) {
            return 1;
        }
    }
    return 0;
}
