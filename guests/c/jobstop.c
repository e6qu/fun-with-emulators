/* Job-control stops of a child with threads, as Linux makes them: a stop
 * stops every thread (counters they bump stand still; one that moved is
 * told, by how much), /proc shows it
 * stopped, the parent's wait reports each stop and continue once, its
 * SIGCHLD tells of them (CLD_STOPPED, CLD_CONTINUED, with the child's pid
 * and the signal) unless SA_NOCLDSTOP asks for none, a stop of SIGTSTP is
 * reported as SIGTSTP's, stops and continues in a storm are all reported,
 * and SIGKILL ends a stopped child at once.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

typedef unsigned long pthread_t;
typedef long ssize_t;
typedef unsigned long size_t;

/* The C library's (glibc's and musl's alike on arm64). */
struct sigaction {
    void (*handler)(int, int *, void *);
    unsigned long mask[16];
    int flags;
    void (*restorer)(void);
};

int pthread_create(pthread_t *thread, const void *attr, void *(*start)(void *), void *arg);
int sigaction(int sig, const struct sigaction *act, struct sigaction *old);
int fork(void);
int kill(int pid, int sig);
int waitpid(int pid, int *status, int options);
int usleep(unsigned usec);
int open(const char *path, int flags, ...);
int close(int fd);
ssize_t read(int fd, void *buf, size_t n);
void *mmap(void *addr, size_t len, int prot, int flags, int fd, long off);
int snprintf(char *s, size_t n, const char *format, ...);
int printf(const char *format, ...);
void _exit(int status);

#define SIGKILL 9
#define SIGCHLD 17
#define SIGCONT 18
#define SIGSTOP 19
#define SIGTSTP 20
#define WUNTRACED 2
#define WCONTINUED 8
#define SA_NOCLDSTOP 1
#define SA_SIGINFO 4
#define SA_RESTART 0x10000000
#define CLD_STOPPED 5
#define CLD_CONTINUED 6
#define MAP_SHARED 1
#define MAP_ANONYMOUS 0x20
#define ROUNDS 300

/* Bumped by the child's threads: [0] its main thread's, [1] and [2] the
 * others'. Shared with the parent. */
static volatile long *count;

/* What the parent's SIGCHLD handler saw. */
static volatile int stops, conts, stop_status, cont_status, from;

static void on_chld(int sig, int *info, void *ctx) {
    (void)sig;
    (void)ctx;
    /* si_code, then si_pid and si_status of the child union. */
    if (info[2] == CLD_STOPPED) {
        stops++;
        stop_status = info[6];
    } else if (info[2] == CLD_CONTINUED) {
        conts++;
        cont_status = info[6];
    }
    from = info[4];
}

static void *bump(void *arg) {
    long i = (long)arg;
    for (;;)
        count[i]++;
    return 0;
}

/* The state letter of process `pid` in /proc. */
static char state_of(int pid) {
    char path[64], buf[512];
    snprintf(path, sizeof path, "/proc/%d/stat", pid);
    int fd = open(path, 0);
    if (fd < 0)
        return '?';
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    for (ssize_t i = n - 1; i > 0; i--)
        if (buf[i] == ')' && i + 2 < n)
            return buf[i + 2];
    return '?';
}

static void handle(int flags) {
    struct sigaction sa = {0};
    sa.handler = on_chld;
    sa.flags = SA_SIGINFO | SA_RESTART | flags;
    sigaction(SIGCHLD, &sa, 0);
}

static int stopped_by(int status) {
    return (status & 0xff) == 0x7f ? (status >> 8) & 0xff : -1;
}

/* Stop the child with `sig` and continue it, waiting for each: whether
 * both were reported. */
static int stop_and_continue(int child, int sig) {
    int status = 0;
    kill(child, sig);
    if (waitpid(child, &status, WUNTRACED) != child || stopped_by(status) != sig)
        return 0;
    kill(child, SIGCONT);
    return waitpid(child, &status, WCONTINUED) == child && status == 0xffff;
}

int main(void) {
    count = mmap(0, 4096, 3, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    handle(0);
    int child = fork();
    if (child == 0) {
        pthread_t t;
        pthread_create(&t, 0, bump, (void *)1);
        pthread_create(&t, 0, bump, (void *)2);
        bump(0);
    }
    while (count[0] == 0 || count[1] == 0 || count[2] == 0)
        usleep(1000);

    int status = 0;
    kill(child, SIGSTOP);
    int reported = waitpid(child, &status, WUNTRACED) == child && stopped_by(status) == SIGSTOP;
    long before[3] = {count[0], count[1], count[2]};
    usleep(50000);
    long mid[3] = {count[0], count[1], count[2]};
    int still = mid[0] == before[0] && mid[1] == before[1] && mid[2] == before[2];
    /* A thread that moved: by how much, and whether it went on moving (a
     * few steps as the stop was told, or not stopped at all). */
    if (!still) {
        usleep(50000);
        for (int i = 0; i < 3; i++)
            printf("thread %d: +%ld in the first 50 ms, +%ld in the next\n", i, mid[i] - before[i],
                   count[i] - mid[i]);
    }
    char state = state_of(child);
    kill(child, SIGCONT);
    int continued = waitpid(child, &status, WCONTINUED) == child && status == 0xffff;
    /* Every thread runs again: soon, on a host as busy as it might be (a
     * thread kept stopped never does). */
    int again = 0;
    for (int i = 0; i < 5000 && !again; i++) {
        usleep(1000);
        again = count[0] != before[0] && count[1] != before[1] && count[2] != before[2];
    }
    printf("stop: reported %d, threads still %d, state %c; continue: reported %d, threads on %d\n",
           reported, still, state, continued, again);
    printf("SIGCHLD: stopped %d (status %d), continued %d (status %d), from the child %d\n", stops,
           stop_status, conts, cont_status, from == child);

    printf("SIGTSTP: %d\n", stop_and_continue(child, SIGTSTP));

    int rounds = 0;
    for (int r = 0; r < ROUNDS; r++)
        rounds += stop_and_continue(child, SIGSTOP);
    printf("storm: %d of %d\n", rounds, ROUNDS);

    handle(SA_NOCLDSTOP);
    usleep(20000);
    stops = conts = 0;
    int both = stop_and_continue(child, SIGSTOP);
    usleep(20000);
    printf("SA_NOCLDSTOP: reported %d, SIGCHLDs %d\n", both, stops + conts);

    kill(child, SIGSTOP);
    waitpid(child, &status, WUNTRACED);
    kill(child, SIGKILL);
    int ended = waitpid(child, &status, 0) == child && (status & 0x7f) == SIGKILL;
    printf("killed while stopped: %d\n", ended);
    return 0;
}
