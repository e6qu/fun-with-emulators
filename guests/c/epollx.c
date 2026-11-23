/* EPOLLEXCLUSIVE across processes, as LTP's epoll_wait16 tests it: eight
 * children each add one pipe's read end, edge-triggered and exclusive, to
 * an epoll set of their own and wait; once /proc shows every one asleep,
 * each byte written to the pipe wakes exactly one of them. A round that
 * wakes none, or more than one, is told with each child's wait.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

typedef long ssize_t;
typedef unsigned long size_t;

struct epoll_event {
    unsigned events;
    unsigned long data;
};

struct timespec {
    long sec, nsec;
};

int fork(void);
int kill(int pid, int sig);
int pipe(int fds[2]);
ssize_t read(int fd, void *buf, size_t n);
ssize_t write(int fd, const void *buf, size_t n);
int open(const char *path, int flags, ...);
int close(int fd);
int epoll_create1(int flags);
int epoll_ctl(int ep, int op, int fd, struct epoll_event *ev);
int epoll_wait(int ep, struct epoll_event *evs, int n, int timeout);
int waitpid(int pid, int *status, int options);
int clock_gettime(int clock, struct timespec *ts);
int snprintf(char *s, size_t n, const char *format, ...);
int printf(const char *format, ...);
char *strrchr(const char *s, int c);
int usleep(unsigned usec);
void *mmap(void *addr, size_t len, int prot, int flags, int fd, long off);
void _exit(int status);

#define NWAITERS 8
#define EPOLL_CTL_ADD 1
#define EPOLLIN 1u
#define EPOLLET (1u << 31)
#define EPOLLEXCLUSIVE (1u << 28)
#define CLOCK_MONOTONIC 1
#define SIGKILL 9

/* Each child's outcome: its wait's result and when it began and ended
 * (ms from the start), in memory the processes share. */
struct outcome {
    int result;
    long began, ended;
};

static long start_ms;

static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.sec * 1000 + t.nsec / 1000000 - start_ms;
}

static char state(int pid) {
    char path[64], buf[512];
    snprintf(path, sizeof path, "/proc/%d/stat", pid);
    int fd = open(path, 0);
    if (fd < 0)
        return '?';
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0)
        return '?';
    buf[n] = 0;
    char *p = strrchr(buf, ')');
    return p ? p[2] : '?';
}

int main(void) {
    start_ms = 0;
    start_ms = now_ms();
    struct outcome *out = mmap(0, 4096, 3, 0x21, -1, 0);
    volatile int *woken = (volatile int *)&out[NWAITERS];
    int fds[2];
    pipe(fds);
    int pids[NWAITERS];
    for (int i = 0; i < NWAITERS; i++) {
        pids[i] = fork();
        if (pids[i] == 0) {
            int ep = epoll_create1(0);
            struct epoll_event ev = {EPOLLIN | EPOLLET | EPOLLEXCLUSIVE, 0};
            epoll_ctl(ep, EPOLL_CTL_ADD, fds[0], &ev);
            out[i].began = now_ms();
            out[i].result = epoll_wait(ep, &ev, 1, 2000);
            out[i].ended = now_ms();
            if (out[i].result == 1)
                __atomic_add_fetch(woken, 1, __ATOMIC_SEQ_CST);
            _exit(0);
        }
    }
    for (int i = 0; i < NWAITERS; i++)
        while (state(pids[i]) != 'S')
            usleep(1000);
    long asleep = now_ms();
    int bad = 0;
    for (int round = 0; round < NWAITERS && !bad; round++) {
        long wrote = now_ms();
        write(fds[1], "x", 1);
        for (int t = 0; t < 3000 && *woken < round + 1; t++)
            usleep(1000);
        usleep(20000);
        if (*woken != round + 1) {
            bad = 1;
            printf("round %d: woke %d in all, written at %ld ms, all asleep at %ld ms\n",
                   round + 1, *woken, wrote, asleep);
        }
        char c;
        read(fds[0], &c, 1);
    }
    for (int i = 0; i < NWAITERS; i++) {
        kill(pids[i], SIGKILL);
        waitpid(pids[i], 0, 0);
    }
    if (bad)
        for (int i = 0; i < NWAITERS; i++)
            printf("  child %d: wait returned %d, began at %ld ms, ended at %ld ms\n", i,
                   out[i].result, out[i].began, out[i].ended);
    printf("each write woke one waiter: %s\n", bad ? "no" : "yes");
    return 0;
}
