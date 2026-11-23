/* SIGURG a process blocks and reads through a signalfd in an epoll set, as
 * PostgreSQL's latches take it, sent by another process again and again,
 * each answered before the next: every one is read, though each lands as
 * the receiver starts its next epoll_wait.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

typedef struct { unsigned long bits[16]; } sigset_t;
typedef long ssize_t;
typedef unsigned long size_t;

struct epoll_event {
    unsigned events;
    unsigned long data;
};

struct pollfd {
    int fd;
    short events;
    short revents;
};

int fork(void);
int kill(int pid, int sig);
int pipe(int fds[2]);
ssize_t read(int fd, void *buf, size_t n);
ssize_t write(int fd, const void *buf, size_t n);
int poll(struct pollfd *fds, unsigned long n, int timeout);
int sigprocmask(int how, const sigset_t *set, sigset_t *old);
int sigemptyset(sigset_t *set);
int sigaddset(sigset_t *set, int sig);
int signalfd(int fd, const sigset_t *mask, int flags);
int epoll_create1(int flags);
int epoll_ctl(int ep, int op, int fd, struct epoll_event *ev);
int epoll_wait(int ep, struct epoll_event *evs, int n, int timeout);
int waitpid(int pid, int *status, int options);
int printf(const char *format, ...);
void _exit(int status);

#define SIGKILL 9
#define SIGURG 23
#define SIG_BLOCK 0
#define EPOLL_CTL_ADD 1
#define EPOLLIN 1
#define POLLIN 1
#define SFD_NONBLOCK 04000
#define ROUNDS 20000

/* Block SIGURG and wait for it through a signalfd, answering each on
 * `ack` ('x' for one never seen). */
static void receive(int ready, int ack) {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGURG);
    sigprocmask(SIG_BLOCK, &set, 0);
    int sfd = signalfd(-1, &set, SFD_NONBLOCK);
    int ep = epoll_create1(0);
    struct epoll_event ev = {EPOLLIN, 0};
    epoll_ctl(ep, EPOLL_CTL_ADD, sfd, &ev);
    write(ready, "r", 1);
    for (;;) {
        if (epoll_wait(ep, &ev, 1, 5000) != 1) {
            write(ack, "x", 1);
            _exit(1);
        }
        char info[128];
        while (read(sfd, info, sizeof info) > 0) {
        }
        write(ack, "a", 1);
    }
}

int main(void) {
    int ack[2], ready[2];
    pipe(ack);
    pipe(ready);
    int child = fork();
    if (child == 0)
        receive(ready[1], ack[1]);
    char c;
    read(ready[0], &c, 1);
    int answered = 0;
    for (int i = 0; i < ROUNDS; i++) {
        kill(child, SIGURG);
        struct pollfd p = {ack[0], POLLIN, 0};
        if (poll(&p, 1, 10000) != 1 || read(ack[0], &c, 1) != 1 || c != 'a')
            break;
        answered++;
    }
    kill(child, SIGKILL);
    waitpid(child, 0, 0);
    printf("SIGURG: %d of %d answered\n", answered, ROUNDS);
    return 0;
}
