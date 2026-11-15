/* Sockets as Linux has them: edges of an eventfd, Unix autobind and raw
 * Unix sockets, a netlink socket's own options. The first argument names
 * the case.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

typedef unsigned long size_t;
typedef unsigned socklen_t;

struct sockaddr_un {
    unsigned short sun_family;
    char sun_path[108];
};

struct epoll_event {
    unsigned events;
    unsigned pad;
    unsigned long long data;
};

int socket(int domain, int type, int protocol);
int socketpair(int domain, int type, int protocol, int sv[2]);
int bind(int fd, const void *addr, socklen_t len);
int connect(int fd, const void *addr, socklen_t len);
int listen(int fd, int backlog);
int accept(int fd, void *addr, socklen_t *len);
int getsockname(int fd, void *addr, socklen_t *len);
int getpeername(int fd, void *addr, socklen_t *len);
int setsockopt(int fd, int level, int name, const void *val, socklen_t len);
int getsockopt(int fd, int level, int name, void *val, socklen_t *len);
long sendto(int fd, const void *buf, size_t n, int flags, const void *addr, socklen_t len);
long recvfrom(int fd, void *buf, size_t n, int flags, void *addr, socklen_t *len);
long send(int fd, const void *buf, size_t n, int flags);
long recv(int fd, void *buf, size_t n, int flags);
long read(int fd, void *buf, size_t n);
long write(int fd, const void *buf, size_t n);
int eventfd(unsigned initval, int flags);
int epoll_create1(int flags);
int epoll_ctl(int ep, int op, int fd, void *event);
int epoll_wait(int ep, void *events, int max, int timeout);
int *__errno_location(void);
int strcmp(const char *a, const char *b);
int printf(const char *format, ...);
void *memset(void *s, int c, size_t n);

#define errno (*__errno_location())
#define AF_UNIX 1
#define AF_NETLINK 16
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOCK_RAW 3
#define SOL_SOCKET 1
#define SO_TYPE 3
#define SO_PASSCRED 16
#define SOL_NETLINK 270
#define EPOLLIN 0x1
#define EPOLLET (1u << 31)

/* An eventfd watched edge-triggered: an edge for every write, whether its
 * count was 0 or not, and none without one. */
static int eventfd_edges(void) {
    int efd = eventfd(0, 0x800);
    int ep = epoll_create1(0);
    struct epoll_event ev = {EPOLLIN | EPOLLET, 0, 1}, out;
    epoll_ctl(ep, 1, efd, &ev);
    unsigned long long one = 1;
    printf("before: %d\n", epoll_wait(ep, &out, 1, 0));
    for (int i = 0; i < 3; i++) {
        write(efd, &one, 8);
        int n = epoll_wait(ep, &out, 1, 1000);
        printf("write %d: %d, then %d\n", i, n, epoll_wait(ep, &out, 1, 0));
    }
    return 0;
}

/* Whether name `a` of length `len` is an autobound one: an abstract name
 * of five hexadecimal digits. */
static int autobound(const struct sockaddr_un *a, socklen_t len) {
    if (len != 8 || a->sun_family != AF_UNIX || a->sun_path[0] != 0)
        return 0;
    for (int i = 1; i < 6; i++) {
        char c = a->sun_path[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return 0;
    }
    return 1;
}

/* A Unix socket bound with its family alone takes an abstract name of the
 * kernel's choosing, and keeps it when asked again; one that passes
 * credentials is given one when it sends unbound or connects. */
static int autobind(void) {
    struct sockaddr_un a, b;
    socklen_t len = sizeof a;
    int s = socket(AF_UNIX, SOCK_DGRAM, 0);
    a.sun_family = AF_UNIX;
    int r = bind(s, &a, 2);
    getsockname(s, &a, &len);
    printf("bind with the family alone: %d, autobound %d\n", r, autobound(&a, len));
    b.sun_family = AF_UNIX;
    r = bind(s, &b, 2);
    len = sizeof b;
    getsockname(s, &b, &len);
    int same = len == 8;
    for (int i = 0; i < 6 && same; i++)
        same = a.sun_path[i] == b.sun_path[i];
    printf("again: %d, same name %d\n", r, same);

    /* A datagram that passes credentials, sent unbound. */
    int tx = socket(AF_UNIX, SOCK_DGRAM, 0), one = 1;
    setsockopt(tx, SOL_SOCKET, SO_PASSCRED, &one, sizeof one);
    sendto(tx, "x", 1, 0, &a, 8);
    char buf[4];
    len = sizeof b;
    memset(&b, 0, sizeof b);
    long n = recvfrom(s, buf, sizeof buf, 0, &b, &len);
    printf("sent with credentials: %ld from autobound %d\n", n, autobound(&b, len));
    /* One that passes none stays unnamed. */
    int plain = socket(AF_UNIX, SOCK_DGRAM, 0);
    sendto(plain, "y", 1, 0, &a, 8);
    len = sizeof b;
    n = recvfrom(s, buf, sizeof buf, 0, &b, &len);
    printf("sent without: %ld from a name of %u bytes\n", n, len);

    /* A stream that passes credentials, connected unbound. */
    int srv = socket(AF_UNIX, SOCK_STREAM, 0);
    bind(srv, &a, 2);
    len = sizeof a;
    getsockname(srv, &a, &len);
    listen(srv, 1);
    int cli = socket(AF_UNIX, SOCK_STREAM, 0);
    setsockopt(cli, SOL_SOCKET, SO_PASSCRED, &one, sizeof one);
    r = connect(cli, &a, len);
    len = sizeof b;
    getsockname(cli, &b, &len);
    printf("connected with credentials: %d, autobound %d\n", r, autobound(&b, len));
    return 0;
}

/* A Unix SOCK_RAW socket is a datagram one. */
static int unix_raw(void) {
    int s = socket(AF_UNIX, SOCK_RAW, 0);
    int ty = -1;
    socklen_t len = sizeof ty;
    getsockopt(s, SOL_SOCKET, SO_TYPE, &ty, &len);
    int sv[2];
    int r = socketpair(AF_UNIX, SOCK_RAW, 0, sv);
    send(sv[0], "ab", 2, 0);
    send(sv[0], "cde", 3, 0);
    char b[8];
    long first = recv(sv[1], b, sizeof b, 0);
    printf("raw: socket %d type %d, pair %d, datagrams %ld %ld\n", s >= 0, ty, r, first,
           recv(sv[1], b, sizeof b, 0));
    return 0;
}

/* A netlink socket's own options: Linux's kept, others refused. */
static int netlink(void) {
    int s = socket(AF_NETLINK, SOCK_RAW, 0);
    int one = 1, zero = 0, v = -1, group = 37;
    socklen_t len;
    int r = setsockopt(s, SOL_NETLINK, 6, &one, sizeof one);
    printf("rx ring: %d errno %d\n", r, errno);
    r = setsockopt(s, 0, 1, &one, sizeof one);
    printf("level 0: %d errno %d\n", r, errno);
    r = setsockopt(s, SOL_NETLINK, 11, &one, 2);
    printf("ext ack, short: %d errno %d\n", r, errno);
    len = sizeof v;
    r = getsockopt(s, SOL_NETLINK, 9, &v, &len);
    printf("memberships before: %d, %u bytes\n", r, len);
    setsockopt(s, SOL_NETLINK, 11, &one, sizeof one);
    len = sizeof v;
    getsockopt(s, SOL_NETLINK, 11, &v, &len);
    printf("ext ack: %d (%u bytes)\n", v, len);
    setsockopt(s, SOL_NETLINK, 11, &zero, sizeof zero);
    len = sizeof v;
    getsockopt(s, SOL_NETLINK, 11, &v, &len);
    printf("ext ack off: %d\n", v);
    r = setsockopt(s, SOL_NETLINK, 1, &group, sizeof group);
    printf("group 37: %d errno %d\n", r, errno);
    r = setsockopt(s, SOL_NETLINK, 1, &zero, sizeof zero);
    printf("group 0: %d errno %d\n", r, errno);
    group = 1;
    setsockopt(s, SOL_NETLINK, 1, &group, sizeof group);
    group = 33;
    setsockopt(s, SOL_NETLINK, 1, &group, sizeof group);
    unsigned words[4] = {0, 0, 0, 0};
    len = sizeof words;
    getsockopt(s, SOL_NETLINK, 9, words, &len);
    printf("memberships: %u bytes, %#x %#x\n", len, words[0], words[1]);
    group = 1;
    setsockopt(s, SOL_NETLINK, 2, &group, sizeof group);
    len = sizeof words;
    getsockopt(s, SOL_NETLINK, 9, words, &len);
    printf("after leaving 1: %#x %#x\n", words[0], words[1]);

    /* An error's acknowledgement: the whole request, or with
     * NETLINK_CAP_ACK its header only. */
    unsigned req[8] = {32, 0x7f | (5u << 16), 1, 0, 0, 0, 0, 0};
    char reply[256];
    send(s, req, sizeof req, 0);
    long whole = recv(s, reply, sizeof reply, 0);
    setsockopt(s, SOL_NETLINK, 10, &one, sizeof one);
    send(s, req, sizeof req, 0);
    long capped = recv(s, reply, sizeof reply, 0);
    printf("error acknowledged in %ld bytes, capped %ld\n", whole, capped);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2)
        return 2;
    if (!strcmp(argv[1], "eventfd"))
        return eventfd_edges();
    if (!strcmp(argv[1], "autobind"))
        return autobind();
    if (!strcmp(argv[1], "raw"))
        return unix_raw();
    if (!strcmp(argv[1], "netlink"))
        return netlink();
    return 2;
}
