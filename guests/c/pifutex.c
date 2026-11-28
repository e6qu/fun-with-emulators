/* Priority-inheritance futexes, as Linux runs them: FUTEX_LOCK_PI takes a
 * word with no owner (its thread id the word), marks one another owns
 * with FUTEX_WAITERS and waits; FUTEX_UNLOCK_PI hands the lock to the
 * oldest waiter (its thread id, with FUTEX_WAITERS, the word), whatever
 * the arguments it does not use hold; a lock
 * interrupted by a signal goes on after the handler, SA_RESTART or not.
 * Then the C library's PTHREAD_PRIO_INHERIT mutexes (musl's
 * pthread_mutexattr_setprotocol tries FUTEX_LOCK_PI first, as PulseAudio
 * finds out), robust ones too.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

typedef unsigned long u64;

int printf(const char *fmt, ...);
long syscall(long nr, ...);
int *__errno_location(void);
int pthread_create(u64 *t, const void *attr, void *(*fn)(void *), void *arg);
int pthread_join(u64 t, void **ret);
int pthread_mutexattr_init(void *a);
int pthread_mutexattr_setprotocol(void *a, int protocol);
int pthread_mutexattr_setrobust(void *a, int robust);
int pthread_mutex_init(void *m, const void *a);
int pthread_mutex_lock(void *m);
int pthread_mutex_unlock(void *m);
int pthread_mutex_consistent(void *m);
int clock_gettime(int clock, void *ts);
int usleep(unsigned us);
int sigaction(int sig, const void *act, void *old);

#define SYS_futex 98
#define SYS_gettid 178
#define SYS_tgkill 131
#define SYS_getpid 172
#define FUTEX_LOCK_PI 6
#define FUTEX_UNLOCK_PI 7
#define FUTEX_TRYLOCK_PI 8
#define FUTEX_PRIVATE 128
#define WAITERS 0x80000000u

struct timespec {
    long sec, nsec;
};

/* glibc's and musl's struct sigaction on arm64 alike. */
struct sigact {
    void (*handler)(int);
    unsigned long mask[16];
    int flags;
    void (*restorer)(void);
};

static volatile unsigned word;

static long futex(volatile unsigned *w, int op, const struct timespec *ts) {
    long r = syscall(SYS_futex, w, op | FUTEX_PRIVATE, 0, ts, 0, 0);
    return r < 0 ? -*__errno_location() : r;
}

/* As futex, with junk in the arguments the operation does not use (its
 * value, timeout and second word), as musl's pthread_mutex_unlock leaves
 * them for FUTEX_UNLOCK_PI: Linux reads none of them. */
static long futex_junk(volatile unsigned *w, int op) {
    long r = syscall(SYS_futex, w, op | FUTEX_PRIVATE, 7, (void *)0x80, (void *)0x80, 7);
    return r < 0 ? -*__errno_location() : r;
}

static unsigned gettid(void) { return (unsigned)syscall(SYS_gettid); }

/* A waiter: its lock's result, and whether the word was its own, with
 * FUTEX_WAITERS, as it took it; then it gives it back. */
static long waited;
static int handed;
static void *waiter(void *arg) {
    (void)arg;
    waited = futex(&word, FUTEX_LOCK_PI, 0);
    handed = word == (gettid() | WAITERS);
    futex(&word, FUTEX_UNLOCK_PI, 0);
    return 0;
}

/* What another thread gets for the word main owns. */
static long others_unlock, others_try, timed;
static void *other(void *arg) {
    (void)arg;
    others_unlock = futex(&word, FUTEX_UNLOCK_PI, 0);
    others_try = futex(&word, FUTEX_TRYLOCK_PI, 0);
    struct timespec ts;
    clock_gettime(0, &ts); /* CLOCK_REALTIME, LOCK_PI's clock */
    ts.nsec += 50000000;
    if (ts.nsec >= 1000000000) {
        ts.sec++;
        ts.nsec -= 1000000000;
    }
    timed = futex(&word, FUTEX_LOCK_PI, &ts);
    return 0;
}

static volatile int caught;
static void on_usr1(int sig) {
    (void)sig;
    caught = 1;
}
static volatile unsigned interrupted_tid;
static long interrupted;
static void *interruptee(void *arg) {
    (void)arg;
    interrupted_tid = gettid();
    interrupted = futex(&word, FUTEX_LOCK_PI, 0);
    futex(&word, FUTEX_UNLOCK_PI, 0);
    return 0;
}

static long mutex[16], attr[2];
static long counter;
static void *counting(void *arg) {
    (void)arg;
    for (int i = 0; i < 2000; i++) {
        pthread_mutex_lock(mutex);
        counter++;
        pthread_mutex_unlock(mutex);
    }
    return 0;
}

static long robust[16];
static void *dies_holding(void *arg) {
    (void)arg;
    pthread_mutex_lock(robust);
    return 0;
}

int main(void) {
    unsigned me = gettid();
    u64 t;

    printf("lock: %ld, the owner's: %d\n", futex(&word, FUTEX_LOCK_PI, 0), word == me);
    printf("again: %ld\n", futex(&word, FUTEX_LOCK_PI, 0));

    pthread_create(&t, 0, waiter, 0);
    usleep(100000);
    printf("a waiter marks it: %d\n", word == (me | WAITERS));
    printf("unlock: %ld\n", futex(&word, FUTEX_UNLOCK_PI, 0));
    pthread_join(t, 0);
    printf("the waiter's lock: %ld, handed to it: %d, then free: %d\n", waited, handed, word == 0);
    long tried = futex_junk(&word, FUTEX_TRYLOCK_PI);
    long unlocked = futex_junk(&word, FUTEX_UNLOCK_PI);
    printf("with junk where unused: try: %ld, unlock: %ld, free: %d\n", tried, unlocked, word == 0);

    futex(&word, FUTEX_LOCK_PI, 0);
    pthread_create(&t, 0, other, 0);
    pthread_join(t, 0);
    printf("another's unlock: %ld, try: %ld, timed lock: %ld\n", others_unlock, others_try,
           timed);
    futex(&word, FUTEX_UNLOCK_PI, 0);

    word = 0x3ffffff0;
    printf("an owner that never ran: %ld\n", futex(&word, FUTEX_LOCK_PI, 0));
    word = 0;

    struct sigact sa = {on_usr1, {0}, 0, 0}; /* no SA_RESTART */
    sigaction(10, &sa, 0);
    futex(&word, FUTEX_LOCK_PI, 0);
    pthread_create(&t, 0, interruptee, 0);
    while (!(word & WAITERS)) usleep(1000);
    syscall(SYS_tgkill, syscall(SYS_getpid), interrupted_tid, 10);
    usleep(100000);
    futex(&word, FUTEX_UNLOCK_PI, 0);
    pthread_join(t, 0);
    printf("interrupted: handler ran %d, then locked: %ld\n", caught, interrupted);

    pthread_mutexattr_init(attr);
    printf("setprotocol: %d\n", pthread_mutexattr_setprotocol(attr, 1)); /* PTHREAD_PRIO_INHERIT */
    pthread_mutex_init(mutex, attr);
    u64 ts[4];
    for (int i = 0; i < 4; i++) pthread_create(&ts[i], 0, counting, 0);
    for (int i = 0; i < 4; i++) pthread_join(ts[i], 0);
    printf("counted: %ld\n", counter);

    pthread_mutexattr_setrobust(attr, 1); /* PTHREAD_MUTEX_ROBUST */
    pthread_mutex_init(robust, attr);
    pthread_create(&t, 0, dies_holding, 0);
    pthread_join(t, 0);
    int died = pthread_mutex_lock(robust);
    printf("its owner ended: %d, made consistent: %d, unlocked: %d\n", died,
           pthread_mutex_consistent(robust), pthread_mutex_unlock(robust));
    return 0;
}
