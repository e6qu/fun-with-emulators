/* Descriptors without O_CLOEXEC keep working across execve, as Linux keeps
 * them: an epoll set (and a duplicate of it) watching a pipe, a timerfd
 * armed before, an eventfd holding a count, and a signalfd for SIGUSR1,
 * which is blocked and pending (both kept across execve too). The first run makes them
 * and runs itself again; with `threaded` it does so with a second thread
 * alive, which makes fwe re-execute itself for the execve rather than
 * load the program in place. The second run reports what it finds.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

typedef long ssize_t;
typedef unsigned long size_t;

struct epoll_event {
    unsigned events;
    unsigned long data;
};

struct itimerspec {
    long interval_sec, interval_nsec, value_sec, value_nsec;
};

int printf(const char *fmt, ...);
int snprintf(char *s, size_t n, const char *fmt, ...);
int fflush(void *f);
long strtol(const char *s, char **end, int base);
int strcmp(const char *a, const char *b);
int pipe(int fds[2]);
ssize_t read(int fd, void *buf, size_t n);
ssize_t write(int fd, const void *buf, size_t n);
int dup(int fd);
int execv(const char *path, char *const argv[]);
int epoll_create1(int flags);
int epoll_ctl(int ep, int op, int fd, struct epoll_event *ev);
int epoll_wait(int ep, struct epoll_event *events, int max, int timeout);
int timerfd_create(int clock, int flags);
int timerfd_settime(int fd, int flags, const struct itimerspec *new, struct itimerspec *old);
int eventfd(unsigned initval, int flags);
int pthread_create(void *thread, const void *attr, void *(*start)(void *), void *arg);
int usleep(unsigned us);
int sigemptyset(void *set);
int sigaddset(void *set, int sig);
int sigprocmask(int how, const void *set, void *old);
int signalfd(int fd, const void *mask, int flags);
int raise(int sig);

#define EPOLL_CTL_ADD 1
#define EPOLLIN 1
#define CLOCK_MONOTONIC 1
#define SIG_BLOCK 0
#define SIGUSR1 10

static void *idle(void *arg) {
    (void)arg;
    for (;;) {
        usleep(100000);
    }
    return 0;
}

/* What epoll set `ep` reports now: the data word of its one ready entry,
 * or -1 for none (or more than one, or an error). */
static long ready(int ep) {
    struct epoll_event ev[2];
    return epoll_wait(ep, ev, 2, 1000) == 1 ? (long)ev[0].data : -1;
}

int main(int argc, char **argv) {
    if (argc == 7) {
        int ep = strtol(argv[1], 0, 10), copy = strtol(argv[2], 0, 10);
        int tfd = strtol(argv[3], 0, 10), efd = strtol(argv[4], 0, 10);
        int w = strtol(argv[5], 0, 10), sfd = strtol(argv[6], 0, 10);
        write(w, "x", 1);
        long seen = ready(ep);
        long through_copy = ready(copy);
        unsigned long expiries = 0, count = 0;
        ssize_t t = read(tfd, &expiries, 8);
        ssize_t e = read(efd, &count, 8);
        unsigned info[32] = {0};
        ssize_t si = read(sfd, info, sizeof info);
        printf("after execve: epoll sees %ld, its duplicate %ld; timerfd %ld bytes, %lu expiry; "
               "eventfd %ld bytes, count %lu; signalfd %ld bytes, signal %u\n",
               seen, through_copy, (long)t, expiries, (long)e, count, (long)si, info[0]);
        return 0;
    }
    int p[2];
    pipe(p);
    int ep = epoll_create1(0);
    int copy = dup(ep);
    struct epoll_event ev = {EPOLLIN, 42};
    epoll_ctl(ep, EPOLL_CTL_ADD, p[0], &ev);
    int tfd = timerfd_create(CLOCK_MONOTONIC, 0);
    struct itimerspec its = {0, 0, 0, 50000000};
    timerfd_settime(tfd, 0, &its, 0);
    int efd = eventfd(5, 0);
    unsigned long mask[16] = {0};
    sigemptyset(mask);
    sigaddset(mask, SIGUSR1);
    sigprocmask(SIG_BLOCK, mask, 0);
    int sfd = signalfd(-1, mask, 0);
    raise(SIGUSR1);
    if (argc > 1 && strcmp(argv[1], "threaded") == 0) {
        long thread;
        pthread_create(&thread, 0, idle, 0);
    }
    char a[6][16];
    int v[6] = {ep, copy, tfd, efd, p[1], sfd};
    char *args[8] = {argv[0]};
    for (int i = 0; i < 6; i++) {
        snprintf(a[i], sizeof a[i], "%d", v[i]);
        args[i + 1] = a[i];
    }
    args[7] = 0;
    /* The timer expires before the new program reads it. */
    usleep(100000);
    fflush(0);
    execv("/proc/self/exe", args);
    printf("execv failed\n");
    return 1;
}
