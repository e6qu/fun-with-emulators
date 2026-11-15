/* Socket options and flags as Linux has them. The first argument names
 * the case.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

typedef unsigned long size_t;
typedef unsigned socklen_t;

struct sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    unsigned sin_addr;
    unsigned char zero[8];
};

int socket(int domain, int type, int protocol);
int bind(int fd, const void *addr, socklen_t len);
int getsockname(int fd, void *addr, socklen_t *len);
int setsockopt(int fd, int level, int name, const void *val, socklen_t len);
int getsockopt(int fd, int level, int name, void *val, socklen_t *len);
long sendto(int fd, const void *buf, size_t n, int flags, const void *addr, socklen_t len);
long recv(int fd, void *buf, size_t n, int flags);
int usleep(unsigned usec);
int listen(int fd, int backlog);
int accept(int fd, void *addr, socklen_t *len);
long read(int fd, void *buf, size_t n);
int close(int fd);
int socketpair(int domain, int type, int protocol, int sv[2]);
int pipe(int fds[2]);
long write(int fd, const void *buf, size_t n);
int shutdown(int fd, int how);
int epoll_create1(int flags);
int epoll_ctl(int ep, int op, int fd, void *event);
int epoll_wait(int ep, void *events, int max, int timeout);

struct pollfd {
    int fd;
    short events, revents;
};
int poll(struct pollfd *fds, unsigned long n, int timeout);

struct epoll_event {
    unsigned events;
    unsigned pad;
    unsigned long long data;
};
int *__errno_location(void);
int strcmp(const char *a, const char *b);
int printf(const char *format, ...);
void *memset(void *s, int c, size_t n);

#define AF_INET 2
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define MSG_FASTOPEN 0x20000000
#define SOL_UDP 17
#define UDP_CORK 1
#define UDP_ENCAP 100
#define UDP_SEGMENT 103
#define MSG_DONTWAIT 0x40
#define errno (*__errno_location())

/* A UDP receiver bound to a loopback port, and its address. */
static int receiver(struct sockaddr_in *a) {
    memset(a, 0, sizeof *a);
    a->sin_family = AF_INET;
    a->sin_addr = 0x0100007f;
    int rx = socket(AF_INET, SOCK_DGRAM, 0);
    bind(rx, a, sizeof *a);
    socklen_t len = sizeof *a;
    getsockname(rx, a, &len);
    return rx;
}

/* The sizes of the datagrams waiting on `rx`, printed. */
static void drain(int rx) {
    char b[64];
    long n;
    usleep(20000);
    while ((n = recv(rx, b, sizeof b, MSG_DONTWAIT)) >= 0)
        printf(" %ld", n);
    printf("\n");
}

/* The UDP level: UDP_CORK holds sends until cleared, UDP_SEGMENT cuts a
 * send into datagrams, an option fwe cannot honour is refused. */
static int udp(void) {
    struct sockaddr_in a;
    int rx = receiver(&a);
    int tx = socket(AF_INET, SOCK_DGRAM, 0);
    int one = 1, zero = 0, four = 4;
    setsockopt(tx, SOL_UDP, UDP_CORK, &one, sizeof one);
    sendto(tx, "ab", 2, 0, &a, sizeof a);
    sendto(tx, "cde", 3, 0, &a, sizeof a);
    printf("corked:");
    drain(rx);
    setsockopt(tx, SOL_UDP, UDP_CORK, &zero, sizeof zero);
    printf("uncorked:");
    drain(rx);
    setsockopt(tx, SOL_UDP, UDP_SEGMENT, &four, sizeof four);
    sendto(tx, "0123456789", 10, 0, &a, sizeof a);
    printf("segmented:");
    drain(rx);
    int r = setsockopt(tx, SOL_UDP, UDP_ENCAP, &one, sizeof one);
    printf("encap: %d errno %d\n", r, errno);
    return 0;
}

/* MSG_FASTOPEN on an unconnected TCP socket connects and sends; on a
 * connected one it is EISCONN. */
static int fastopen(void) {
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr = 0x0100007f;
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    bind(srv, &a, sizeof a);
    socklen_t len = sizeof a;
    getsockname(srv, &a, &len);
    listen(srv, 1);
    int cli = socket(AF_INET, SOCK_STREAM, 0);
    long sent = sendto(cli, "hello", 5, MSG_FASTOPEN, &a, sizeof a);
    int conn = accept(srv, 0, 0);
    char b[8];
    long got = read(conn, b, sizeof b);
    long again = sendto(cli, "x", 1, MSG_FASTOPEN, &a, sizeof a);
    printf("fast open: sent %ld, read %ld, again %ld errno %d\n", sent, got, again, errno);
    return 0;
}

/* SO_PROTOCOL is the protocol a socket was made with (ICMP for a ping
 * socket); a Unix socket's error queue is empty (EAGAIN). */
static int protocol(void) {
    int ping = socket(AF_INET, SOCK_DGRAM, 1);
    int p = -1;
    socklen_t len = sizeof p;
    getsockopt(ping, 1, 38, &p, &len);
    int sv[2];
    socketpair(1, SOCK_DGRAM, 0, sv);
    char b[4];
    long r = recv(sv[0], b, sizeof b, 0x2000);
    printf("ping protocol %d, unix error queue %ld errno %d\n", p, r, errno);
    return 0;
}

/* poll and epoll events by Linux's numbers: a pipe's write end is
 * POLLWRNORM, a socket's POLLWRBAND too, POLLMSG never; a stream whose peer
 * shut its writing is POLLRDHUP; epoll's EPOLLRDNORM is a read. */
static int events(void) {
    int p[2], sv[2], other[2];
    pipe(p);
    socketpair(1, SOCK_STREAM, 0, sv);
    socketpair(1, SOCK_STREAM, 0, other);
    struct pollfd fds[3] = {{p[1], 0x100 | 0x400, 0}, {other[0], 0x200, 0}, {sv[1], 0x2001, 0}};
    shutdown(sv[0], 1);
    int n = poll(fds, 3, 1000);
    printf("poll %d: %#x %#x %#x\n", n, fds[0].revents, fds[1].revents, fds[2].revents & 0x2001);
    write(p[1], "x", 1);
    int ep = epoll_create1(0);
    struct epoll_event ev = {0x40, 0, 7}, out;
    epoll_ctl(ep, 1, p[0], &ev);
    n = epoll_wait(ep, &out, 1, 1000);
    printf("epoll %d: %#x\n", n, out.events);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2)
        return 2;
    if (!strcmp(argv[1], "events"))
        return events();
    if (!strcmp(argv[1], "protocol"))
        return protocol();
    if (!strcmp(argv[1], "fastopen"))
        return fastopen();
    if (!strcmp(argv[1], "udp"))
        return udp();
    return 2;
}
