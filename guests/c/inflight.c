/* A socket passed with SCM_RIGHTS and closed by its sender, with data
 * written into it, as Firefox's fork server is handed its exec socket:
 * whatever happens before the receiver takes it (here another Unix
 * socket, holding a descriptor, goes away), the receiver reads the data.
 * The same for a socket passed with an eventfd, which goes in a bundle of
 * fwe's own. */
int printf(const char *fmt, ...);
int socketpair(int domain, int type, int protocol, int fds[2]);
long sendmsg(int fd, const void *m, int flags);
long recvmsg(int fd, void *m, int flags);
long read(int fd, void *buf, unsigned long n);
long write(int fd, const void *buf, unsigned long n);
int close(int fd);
int eventfd(unsigned v, int flags);
int usleep(unsigned us);
void *memset(void *p, int c, unsigned long n);
void *memcpy(void *d, const void *s, unsigned long n);

struct iovec { void *base; unsigned long len; };
struct msghdr { void *name; unsigned namelen; struct iovec *iov; unsigned long iovlen; void *control; unsigned long controllen; int flags; };
#define AF_UNIX 1
#define SOCK_STREAM 1
#define SOL_SOCKET 1
#define SCM_RIGHTS 1

static int send_fds(int s, const int *fds, int n) {
    char b = 'x';
    struct iovec io = {&b, 1};
    char ctl[16 + 4 * 4];
    memset(ctl, 0, sizeof ctl);
    unsigned long len = 16 + 4 * n;
    memcpy(ctl, &len, 8);
    int level = SOL_SOCKET, type = SCM_RIGHTS;
    memcpy(ctl + 8, &level, 4);
    memcpy(ctl + 12, &type, 4);
    memcpy(ctl + 16, fds, 4 * n);
    struct msghdr m = {0, 0, &io, 1, ctl, (len + 7) & ~7ul, 0};
    return (int)sendmsg(s, &m, 0);
}

static int recv_fd(int s) {
    char b;
    struct iovec io = {&b, 1};
    char ctl[64];
    memset(ctl, 0, sizeof ctl);
    struct msghdr m = {0, 0, &io, 1, ctl, sizeof ctl, 0};
    if (recvmsg(s, &m, 0) != 1 || m.controllen < 20) return -1;
    int fd;
    memcpy(&fd, ctl + 16, 4);
    return fd;
}

/* Another Unix socket, with a descriptor in flight in it, goes away. */
static void some_socket_goes(void) {
    int o[2];
    socketpair(AF_UNIX, SOCK_STREAM, 0, o);
    send_fds(o[0], &o[1], 1);
    close(o[0]);
    close(o[1]);
    usleep(20000);
}

static int run(int with_eventfd) {
    int lost = 0;
    for (int i = 0; i < 10; i++) {
        int chan[2], pair[2];
        socketpair(AF_UNIX, SOCK_STREAM, 0, chan);
        socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
        int ev = eventfd(0, 0);
        int fds[2] = {pair[1], ev};
        send_fds(chan[0], fds, with_eventfd ? 2 : 1);
        close(pair[1]);
        close(ev);
        write(pair[0], "exec info", 9);
        some_socket_goes();
        int got = recv_fd(chan[1]);
        char buf[16] = {0};
        if (got < 0 || read(got, buf, sizeof buf - 1) != 9) lost++;
        close(got);
        close(pair[0]);
        close(chan[0]);
        close(chan[1]);
    }
    return lost;
}

int main(void) {
    printf("socket: data lost in %d of 10\n", run(0));
    printf("socket and eventfd: data lost in %d of 10\n", run(1));
    return 0;
}
