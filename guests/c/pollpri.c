/* What poll reports for a pipe and socket pairs holding data, asked for
 * every input event: Linux gives POLLIN and POLLRDNORM for them, never
 * POLLPRI (urgent data), which NSPR takes for an error; select finds a
 * pipe holding data not exceptional. A TCP socket's urgent data is
 * POLLPRI, a wait for it ends when it comes, and the socket hangs up only
 * once shut both ways. */
struct pollfd { int fd; short events, revents; };
int pipe(int fd[2]);
int socketpair(int domain, int type, int protocol, int sv[2]);
long write(int fd, const void *b, unsigned long n);
int close(int fd);
int poll(struct pollfd *fds, unsigned long n, int timeout);
int printf(const char *fmt, ...);
struct timeval { long sec, usec; };
int select(int n, unsigned long *r, unsigned long *w, unsigned long *e, struct timeval *t);
int socket(int domain, int type, int protocol);
int bind(int fd, const void *a, unsigned len);
int listen(int fd, int n);
int connect(int fd, const void *a, unsigned len);
int accept(int fd, void *a, unsigned *len);
int getsockname(int fd, void *a, unsigned *len);
long send(int fd, const void *b, unsigned long n, int flags);
int usleep(unsigned us);
int fork(void);
int waitpid(int pid, int *status, int options);
int clock_gettime(int clock, void *ts);
int epoll_create1(int flags);
int epoll_ctl(int ep, int op, int fd, void *ev);
int epoll_wait(int ep, void *evs, int n, int timeout);
void _exit(int status);

static void show(const char *what, int rd, int wr) {
    /* POLLIN | POLLPRI | POLLRDNORM | POLLRDBAND */
    struct pollfd p = {rd, 0x1 | 0x2 | 0x40 | 0x80, 0};
    poll(&p, 1, 0);
    printf("%s empty: %#x\n", what, p.revents);
    write(wr, "I", 1);
    p.revents = 0;
    poll(&p, 1, 0);
    printf("%s with data: %#x\n", what, p.revents);
    close(wr);
    p.revents = 0;
    poll(&p, 1, 0);
    printf("%s with data, writer gone: %#x\n", what, p.revents);
    close(rd);
}

int main(void) {
    int fd[2];
    pipe(fd);
    write(fd[1], "I", 1);
    /* A pipe holding data is not exceptional to select. */
    unsigned long rs = 1ul << fd[0], es = 1ul << fd[0];
    struct timeval tv = {0, 0};
    int n = select(fd[0] + 1, &rs, 0, &es, &tv);
    printf("select: %d, read %d, except %d\n", n, (int)(rs >> fd[0] & 1), (int)(es >> fd[0] & 1));
    /* A wait for urgent data alone waits. */
    struct pollfd only = {fd[0], 0x2, 0};
    printf("poll for urgent data: %d, %#x\n", poll(&only, 1, 20), only.revents);
    close(fd[0]);
    close(fd[1]);
    pipe(fd);
    show("pipe", fd[0], fd[1]);
    socketpair(1, 1, 0, fd);
    show("stream pair", fd[0], fd[1]);
    socketpair(1, 2, 0, fd);
    show("datagram pair", fd[0], fd[1]);
    /* A TCP socket's urgent data is POLLPRI. */
    int l = socket(2, 1, 0);
    struct { unsigned short f, port; unsigned a; char z[8]; } a = {2, 0, 0x0100007f, {0}};
    unsigned len = sizeof a;
    bind(l, &a, sizeof a);
    listen(l, 1);
    getsockname(l, &a, &len);
    int c = socket(2, 1, 0);
    connect(c, &a, sizeof a);
    int s = accept(l, 0, 0);
    struct pollfd t = {s, 0x1 | 0x2 | 0x40 | 0x80, 0};
    poll(&t, 1, 0);
    printf("tcp empty: %#x\n", t.revents);
    /* A wait for urgent data ends when it comes (the sender's after
     * 50 ms). */
    int pid = fork();
    if (pid == 0) {
        usleep(50000);
        send(c, "U", 1, 1 /* MSG_OOB */);
        _exit(0);
    }
    struct pollfd urg = {s, 0x2, 0};
    printf("tcp poll for urgent data: %d, %#x\n", poll(&urg, 1, 5000), urg.revents);
    waitpid(pid, 0, 0);
    t.revents = 0;
    poll(&t, 1, 0);
    printf("tcp with urgent data: %#x\n", t.revents);
    unsigned long tr[16] = {0}, te[16] = {0};
    tr[s / 64] = te[s / 64] = 1ul << (s % 64);
    struct timeval z = {0, 0};
    int sel = select(s + 1, tr, 0, te, &z);
    printf("tcp select: %d, read %d, except %d\n", sel, (int)(tr[s / 64] >> (s % 64) & 1),
           (int)(te[s / 64] >> (s % 64) & 1));
    close(c);
    usleep(50000);
    t.revents = 0;
    poll(&t, 1, 0);
    printf("tcp with urgent data, peer gone: %#x\n", t.revents);
    /* With its peer's end of the stream come, a TCP socket has not hung
     * up: a wait for urgent data waits, and it can be written. */
    c = socket(2, 1, 0);
    connect(c, &a, sizeof a);
    s = accept(l, 0, 0);
    close(c);
    usleep(50000);
    struct ts { long s, ns; } t0, t1;
    clock_gettime(1, &t0);
    urg.fd = s;
    urg.revents = 0;
    int got = poll(&urg, 1, 200);
    clock_gettime(1, &t1);
    long ms = (t1.s - t0.s) * 1000 + (t1.ns - t0.ns) / 1000000;
    printf("tcp peer gone, poll for urgent data: %d, %#x, waited %s\n", got, urg.revents,
           ms >= 150 ? "its time" : "less");
    struct pollfd w = {s, 0x4, 0};
    poll(&w, 1, 0);
    printf("tcp peer gone, writable: %#x\n", w.revents);
    /* So does epoll's. */
    int ep = epoll_create1(0);
    struct { unsigned events; unsigned long data; } ev = {0x2, 0}, out[2];
    epoll_ctl(ep, 1, s, &ev);
    clock_gettime(1, &t0);
    got = epoll_wait(ep, out, 2, 200);
    clock_gettime(1, &t1);
    ms = (t1.s - t0.s) * 1000 + (t1.ns - t0.ns) / 1000000;
    printf("tcp peer gone, epoll for urgent data: %d, waited %s\n", got,
           ms >= 150 ? "its time" : "less");
    return 0;
}
