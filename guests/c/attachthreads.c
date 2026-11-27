/* A crash reporter's attach, as crashpad's: a child the process allowed
 * (PR_SET_PTRACER) attaches to the process, waits for its stop, then
 * attaches to each of its other threads by id and waits for each one's
 * stop (__WALL); the threads are blocked in ppoll and in a sleep. Each
 * wait reports the thread's SIGSTOP; an alarm ends a tracer whose wait
 * never returns.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

typedef unsigned long pthread_t;
typedef long ssize_t;
typedef unsigned long size_t;

long ptrace(int request, ...);
long syscall(long n, ...);
int prctl(int option, ...);
int fork(void);
int getppid(void);
int pipe(int fds[2]);
ssize_t read(int fd, void *buf, size_t n);
ssize_t write(int fd, const void *buf, size_t n);
int usleep(unsigned us);
unsigned alarm(unsigned s);
int waitpid(int pid, int *status, int options);
int pthread_create(pthread_t *t, const void *attr, void *(*f)(void *), void *arg);
int printf(const char *format, ...);
int fflush(void *f);
void _exit(int status);

struct pollfd {
    int fd;
    short events, revents;
};
int ppoll(struct pollfd *fds, unsigned long n, const void *timeout, const void *sigmask);

#define SYS_gettid 178
#define PTRACE_ATTACH 16
#define PTRACE_DETACH 17
#define PR_SET_PTRACER 0x59616d61
#define WALL 0x40000000

static int tids[2], quiet[2];

static void *polling(void *arg) {
    (void)arg;
    int tid = syscall(SYS_gettid);
    write(tids[1], &tid, sizeof tid);
    struct pollfd p = {quiet[0], 1, 0};
    for (;;) ppoll(&p, 1, 0, 0);
    return 0;
}

static void *sleeping(void *arg) {
    (void)arg;
    int tid = syscall(SYS_gettid);
    write(tids[1], &tid, sizeof tid);
    for (;;) usleep(1000);
    return 0;
}

static void report(const char *who, int r, int status) {
    if (r < 0) printf("%s: wait failed\n", who);
    else if ((status & 0xff) == 0x7f) printf("%s: stopped by %d\n", who, (status >> 8) & 0xff);
    else printf("%s: status %#x\n", who, status);
}

int main(void) {
    pipe(tids);
    pipe(quiet);
    pthread_t t;
    pthread_create(&t, 0, polling, 0);
    pthread_create(&t, 0, sleeping, 0);
    int ids[2];
    read(tids[0], &ids[0], sizeof ids[0]);
    read(tids[0], &ids[1], sizeof ids[1]);
    prctl(PR_SET_PTRACER, -1L, 0L, 0L, 0L);
    fflush(0);
    int tracer = fork();
    if (tracer == 0) {
        int target = getppid(), status = 0;
        alarm(10);
        if (ptrace(PTRACE_ATTACH, target, 0, 0) != 0) _exit(2);
        report("process", waitpid(target, &status, WALL), status);
        const char *names[2] = {"thread in ppoll", "thread sleeping"};
        for (int i = 0; i < 2; i++) {
            if (ptrace(PTRACE_ATTACH, ids[i], 0, 0) != 0) {
                printf("%s: attach failed\n", names[i]);
                continue;
            }
            report(names[i], waitpid(ids[i], &status, WALL), status);
        }
        for (int i = 0; i < 2; i++) ptrace(PTRACE_DETACH, ids[i], 0, 0);
        ptrace(PTRACE_DETACH, target, 0, 0);
        fflush(0);
        _exit(0);
    }
    int status = 0;
    waitpid(tracer, &status, 0);
    if ((status & 0x7f) == 0) printf("tracer: exit %d\n", (status >> 8) & 0xff);
    else printf("tracer: killed by %d\n", status & 0x7f);
    return 0;
}
