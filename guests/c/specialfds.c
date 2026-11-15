/* Pipes, eventfds and signalfds as Linux has them. The first argument
 * names the case.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

typedef unsigned long size_t;

int pipe2(int fds[2], int flags);
long read(int fd, void *buf, size_t n);
long write(int fd, const void *buf, size_t n);
int fork(void);
int waitpid(int pid, int *status, int options);
void _exit(int status);
int usleep(unsigned usec);
int ualarm(unsigned usecs, unsigned interval);

struct sigaction {
    void (*handler)(int);
    unsigned long mask[16];
    int flags;
    void (*restorer)(void);
};
int sigaction(int sig, const struct sigaction *act, struct sigaction *old);
int eventfd(unsigned initval, int flags);
int *__errno_location(void);
int strcmp(const char *a, const char *b);
int printf(const char *format, ...);

#define O_EXCL 0200
#define O_NOTIFICATION_PIPE O_EXCL
#define errno (*__errno_location())

/* Flags Linux does not know are EINVAL; a notification pipe, which needs
 * the watch queue, is ENOPKG. */
static int flags(void) {
    int fds[2];
    int a = pipe2(fds, 01);
    int ea = errno;
    int b = pipe2(fds, O_NOTIFICATION_PIPE);
    int eb = errno;
    int c = eventfd(0, 010);
    int ec = errno;
    printf("pipe2 %d errno %d, notification pipe %d errno %d, eventfd %d errno %d\n", a, ea, b,
           eb, c, ec);
    return 0;
}

static void caught(int sig) { (void)sig; }

/* A write that would take an eventfd's count past its maximum waits for
 * a read; a signal ends the wait with EINTR. */
static int overflow(void) {
    int efd = eventfd(0, 0);
    unsigned long long big = 0xfffffffffffffffdULL, five = 5, got = 0;
    write(efd, &big, 8);
    struct sigaction act = {caught, {0}, 0, 0};
    sigaction(14, &act, 0);
    ualarm(50000, 0);
    long interrupted = write(efd, &five, 8);
    int e = errno;
    int child = fork();
    if (child == 0) {
        usleep(50000);
        read(efd, &got, 8);
        _exit(0);
    }
    long waited = write(efd, &five, 8);
    int status;
    waitpid(child, &status, 0);
    read(efd, &got, 8);
    printf("interrupted %ld errno %d, after a read %ld, count %llu\n", interrupted, e, waited, got);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2)
        return 2;
    if (!strcmp(argv[1], "overflow"))
        return overflow();
    if (!strcmp(argv[1], "flags"))
        return flags();
    return 2;
}
