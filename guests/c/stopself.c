/* A process that stops itself (a handler's raise(SIGSTOP)), continued by
 * its parent as soon as the parent sees it stopped, again and again, while
 * other threads of it run: each stop and each continue is reported to the
 * parent (WUNTRACED, WCONTINUED), as on Linux (macOS on its own can leave a
 * process that stops itself suspended, though shown as running, when a
 * SIGCONT comes as it stops). The child's SIGCONT handler takes each
 * SIGCONT once: it writes a byte for each, which the parent reads, and none
 * is left over. Prints "ok", or what went wrong.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

typedef unsigned long pthread_t;
typedef long ssize_t;
typedef unsigned long size_t;

/* The C library's (glibc's and musl's alike on arm64). */
struct sigaction {
    void (*handler)(int);
    unsigned long mask[16];
    int flags;
    void (*restorer)(void);
};

int pthread_create(pthread_t *thread, const void *attr, void *(*start)(void *), void *arg);
int sigaction(int sig, const struct sigaction *act, struct sigaction *old);
int fork(void);
int kill(int pid, int sig);
int raise(int sig);
int waitpid(int pid, int *status, int options);
int sched_yield(void);
int usleep(unsigned usec);
int pipe(int fds[2]);
ssize_t read(int fd, void *buf, size_t n);
ssize_t write(int fd, const void *buf, size_t n);
int fcntl(int fd, int cmd, ...);
int printf(const char *format, ...);
void _exit(int status);

#define SIGKILL 9
#define SIGUSR1 10
#define SIGSTOP 19
#define SIGCONT 18
#define WUNTRACED 2
#define WCONTINUED 8
#define SA_RESTART 0x10000000
#define F_SETFL 4
#define O_NONBLOCK 04000
#define THREADS 3
#define ROUNDS 400

static int conts[2];

static void on_usr1(int sig) {
    (void)sig;
    raise(SIGSTOP);
}

static void on_cont(int sig) {
    (void)sig;
    write(conts[1], "c", 1);
}

static void *spin(void *arg) {
    (void)arg;
    for (;;)
        sched_yield();
    return 0;
}

int main(void) {
    if (pipe(conts) != 0)
        return 2;
    int child = fork();
    if (child == 0) {
        struct sigaction sa = {0};
        sa.flags = SA_RESTART;
        sa.handler = on_usr1;
        sigaction(SIGUSR1, &sa, 0);
        sa.handler = on_cont;
        sigaction(SIGCONT, &sa, 0);
        pthread_t t;
        for (int i = 0; i < THREADS; i++)
            pthread_create(&t, 0, spin, 0);
        /* Ready: the handlers are in place. */
        write(conts[1], "r", 1);
        for (;;)
            sched_yield();
    }
    char b;
    if (read(conts[0], &b, 1) != 1 || b != 'r') {
        printf("child not ready\n");
        return 1;
    }
    for (int r = 0; r < ROUNDS; r++) {
        int status = 0;
        kill(child, SIGUSR1);
        if (waitpid(child, &status, WUNTRACED) != child || (status & 0xff) != 0x7f ||
            ((status >> 8) & 0xff) != SIGSTOP) {
            printf("round %d: stop reported as %#x\n", r, status);
            kill(child, SIGKILL);
            return 1;
        }
        kill(child, SIGCONT);
        if (waitpid(child, &status, WCONTINUED) != child || status != 0xffff) {
            printf("round %d: continue reported as %#x\n", r, status);
            kill(child, SIGKILL);
            return 1;
        }
        /* Its SIGCONT handler ran for this continue. */
        if (read(conts[0], &b, 1) != 1 || b != 'c') {
            printf("round %d: no SIGCONT taken\n", r);
            kill(child, SIGKILL);
            return 1;
        }
    }
    kill(child, SIGKILL);
    waitpid(child, 0, 0);
    fcntl(conts[0], F_SETFL, O_NONBLOCK);
    int extra = 0;
    while (read(conts[0], &b, 1) == 1)
        extra++;
    if (extra != 0) {
        printf("SIGCONTs taken more than once: %d\n", extra);
        return 1;
    }
    printf("ok\n");
    return 0;
}
