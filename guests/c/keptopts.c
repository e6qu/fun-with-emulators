/* Socket options fwe keeps itself (SO_PASSCRED, SO_PRIORITY, SO_NO_CHECK)
 * are the socket's, as on Linux: a dup of it shares them (a change
 * through one shows through the other, and they outlive a closed dup),
 * and so do a fork child, the program execve runs, and a process the
 * socket is passed to (SCM_RIGHTS). */
struct iovec { void *base; unsigned long len; };
struct msghdr {
    void *name; unsigned namelen; struct iovec *iov; unsigned long iovlen;
    void *control; unsigned long controllen; int flags;
};
int socket(int domain, int type, int protocol);
int socketpair(int domain, int type, int protocol, int sv[2]);
int setsockopt(int fd, int level, int name, const void *val, unsigned len);
int getsockopt(int fd, int level, int name, void *val, unsigned *len);
long sendmsg(int fd, const struct msghdr *m, int flags);
long recvmsg(int fd, struct msghdr *m, int flags);
int dup(int fd);
int close(int fd);
int fork(void);
int waitpid(int pid, int *status, int options);
int execv(const char *path, char *const argv[]);
int printf(const char *fmt, ...);
int fflush(void *f);
int snprintf(char *buf, unsigned long n, const char *fmt, ...);
int atoi(const char *s);
int strcmp(const char *a, const char *b);
void *memcpy(void *d, const void *s, unsigned long n);
void _exit(int status);

static void show(const char *who, int fd) {
    int v[3];
    int names[3] = {16 /* SO_PASSCRED */, 12 /* SO_PRIORITY */, 11 /* SO_NO_CHECK */};
    for (int i = 0; i < 3; i++) {
        unsigned len = sizeof v[i];
        if (getsockopt(fd, 1, names[i], &v[i], &len) != 0) v[i] = -1;
    }
    printf("%s: passcred %d, priority %d, no_check %d\n", who, v[0], v[1], v[2]);
    fflush(0);
}

static void pass(int over, int fd) {
    char c = 'x';
    struct iovec iov = {&c, 1};
    union { char buf[24]; long align; } ctl = {{0}};
    unsigned *h = (unsigned *)ctl.buf;
    ((unsigned long *)ctl.buf)[0] = 20;   /* cmsg_len */
    h[2] = 1;                              /* SOL_SOCKET */
    h[3] = 1;                              /* SCM_RIGHTS */
    memcpy(ctl.buf + 16, &fd, 4);
    struct msghdr m = {0, 0, &iov, 1, ctl.buf, 24, 0};
    sendmsg(over, &m, 0);
}

static int take(int over) {
    char c;
    struct iovec iov = {&c, 1};
    union { char buf[24]; long align; } ctl = {{0}};
    struct msghdr m = {0, 0, &iov, 1, ctl.buf, 24, 0};
    if (recvmsg(over, &m, 0) != 1) return -1;
    int fd;
    memcpy(&fd, ctl.buf + 16, 4);
    return fd;
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "exec") == 0) {
        show("after execve", atoi(argv[2]));
        return 0;
    }
    int s = socket(1, 2, 0);
    int on = 1, prio = 5;
    setsockopt(s, 1, 16, &on, sizeof on);
    setsockopt(s, 1, 12, &prio, sizeof prio);
    setsockopt(s, 1, 11, &on, sizeof on);
    show("the socket", s);
    int d = dup(s);
    show("a dup of it", d);
    prio = 3;
    setsockopt(d, 1, 12, &prio, sizeof prio);
    show("the socket after the dup's change", s);
    close(s);
    show("the dup, the socket's descriptor closed", d);
    s = d;
    int sv[2];
    socketpair(1, 1, 0, sv);
    int pid = fork();
    if (pid == 0) {
        close(sv[0]);
        int got = take(sv[1]);
        show("passed to another process", got);
        _exit(0);
    }
    close(sv[1]);
    /* The child's own copy closed by the time it reads: the socket lives
     * only in the message. */
    int t = socket(1, 2, 0);
    setsockopt(t, 1, 16, &on, sizeof on);
    pass(sv[0], t);
    close(t);
    waitpid(pid, 0, 0);
    pid = fork();
    if (pid == 0) {
        show("in a fork child", s);
        char fd[16];
        snprintf(fd, sizeof fd, "%d", s);
        char *args[] = {argv[0], "exec", fd, 0};
        execv("/proc/self/exe", args);
        _exit(1);
    }
    waitpid(pid, 0, 0);
    return 0;
}
