/* A connect is made once, however signals land: blocking connects while a
 * child keeps sending the process a signal it ignores (SIGWINCH, which
 * interrupts nothing on Linux) all succeed; and a non-blocking connect
 * left in progress is finished by the next connect, which returns 0 once
 * the connection is made, after which the socket is connected (EISCONN).
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

int socket(int domain, int type, int protocol);
int bind(int fd, const void *addr, unsigned len);
int listen(int fd, int backlog);
int accept(int fd, void *addr, void *len);
int connect(int fd, const void *addr, unsigned len);
int getsockname(int fd, void *addr, unsigned *len);
int poll(void *fds, unsigned long n, int timeout);
int close(int fd);
int fork(void);
int getpid(void);
int kill(int pid, int sig);
void _exit(int status);
int waitpid(int pid, int *status, int options);
int printf(const char *format, ...);
int *__errno_location(void);

#define AF_INET 2
#define SOCK_STREAM 1
#define SOCK_NONBLOCK 04000
#define SIGKILL 9
#define SIGWINCH 28
#define POLLOUT 4

struct sin {
    unsigned short family, port;
    unsigned addr;
    char zero[8];
};

struct pollfd {
    int fd;
    short events, revents;
};

int main(void) {
    struct sin a = {AF_INET, 0, 0x0100007f, {0}};
    unsigned len = sizeof a;
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0 || bind(srv, &a, len) || listen(srv, 128) || getsockname(srv, &a, &len))
        return 2;
    int parent = getpid();
    int acceptor = fork();
    if (acceptor < 0)
        return 2;
    if (acceptor == 0) {
        for (;;) {
            int c = accept(srv, 0, 0);
            if (c >= 0)
                close(c);
        }
    }
    int sender = fork();
    if (sender < 0)
        return 2;
    if (sender == 0) {
        for (;;)
            if (kill(parent, SIGWINCH) != 0)
                _exit(0);
    }
    int failed = 0;
    for (int i = 0; i < 200; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(fd, &a, sizeof a) != 0)
            failed++;
        close(fd);
    }
    kill(sender, SIGKILL);
    waitpid(sender, 0, 0);
    printf("blocking connects failed: %d\n", failed);

    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    int first = connect(fd, &a, sizeof a) == 0 ? 0 : *__errno_location();
    struct pollfd p = {fd, POLLOUT, 0};
    poll(&p, 1, 5000);
    int second = connect(fd, &a, sizeof a) == 0 ? 0 : *__errno_location();
    int third = connect(fd, &a, sizeof a) == 0 ? 0 : *__errno_location();
    printf("non-blocking: %d, then %d, then %d\n", first, second, third);
    kill(acceptor, SIGKILL);
    waitpid(acceptor, 0, 0);
    return 0;
}
