/* Sockets and network namespaces, as Linux has them. The first argument
 * names the case.
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
struct sockaddr_un {
    unsigned short sun_family;
    char sun_path[108];
};

int socket(int domain, int type, int protocol);
int bind(int fd, const void *addr, socklen_t len);
int connect(int fd, const void *addr, socklen_t len);
int getsockname(int fd, void *addr, socklen_t *len);
int getpeername(int fd, void *addr, socklen_t *len);
long recvfrom(int fd, void *buf, size_t n, int flags, void *addr, socklen_t *len);
long sendto(int fd, const void *buf, size_t n, int flags, const void *addr, socklen_t len);
long send(int fd, const void *buf, size_t n, int flags);
long recv(int fd, void *buf, size_t n, int flags);
int unshare(int flags);
int ioctl(int fd, unsigned long req, ...);
int getpid(void);
int usleep(unsigned usec);
int *__errno_location(void);
int strcmp(const char *a, const char *b);
int printf(const char *format, ...);
int snprintf(char *s, size_t n, const char *format, ...);
size_t strlen(const char *s);
void *memset(void *s, int c, size_t n);

#define AF_UNIX 1
#define AF_INET 2
#define SOCK_DGRAM 2
#define CLONE_NEWNET 0x40000000
#define MSG_DONTWAIT 0x40
#define SIOCSIFFLAGS 0x8914
#define IFF_UP 1
#define errno (*__errno_location())

static unsigned short htons(unsigned short v) { return (unsigned short)(v << 8 | v >> 8); }

static struct sockaddr_in loopback(unsigned short port) {
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr = 0x0100007f;
    return a;
}

/* An abstract Unix address: its length. */
static socklen_t abstract(struct sockaddr_un *a, const char *name) {
    memset(a, 0, sizeof *a);
    a->sun_family = AF_UNIX;
    size_t n = strlen(name);
    for (size_t i = 0; i < n; i++)
        a->sun_path[1 + i] = name[i];
    return (socklen_t)(2 + 1 + n);
}

/* A socket stays in the namespace it was made in: one made before
 * unshare binds the initial namespace's loopback and abstract names, one
 * made after binds the new namespace's (whose lo is down). */
static int pinned(void) {
    int early_inet = socket(AF_INET, SOCK_DGRAM, 0);
    int early_unix = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (unshare(CLONE_NEWNET) != 0)
        return printf("unshare: %d\n", errno), 1;
    int late_inet = socket(AF_INET, SOCK_DGRAM, 0);
    int late_unix = socket(AF_UNIX, SOCK_DGRAM, 0);
    struct sockaddr_in a = loopback(0);
    int early = bind(early_inet, &a, sizeof a);
    int late = bind(late_inet, &a, sizeof a);
    int late_errno = errno;
    char name[64];
    snprintf(name, sizeof name, "fwe-pinned-%d", getpid());
    struct sockaddr_un u;
    socklen_t len = abstract(&u, name);
    int first = bind(early_unix, &u, len);
    int second = bind(late_unix, &u, len);
    printf("early inet %d, late inet %d errno %d, abstract name in each %d %d\n", early, late,
           late_errno, first, second);
    return 0;
}

/* In a namespace, a datagram to a loopback port nobody bound there goes
 * nowhere: not to the host's port of that number (which a socket of the
 * initial namespace holds here), and a connected sender is told the port
 * is unreachable. A reply to a socket that never bound reaches it. */
static int unbound(void) {
    int host = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = loopback(0);
    bind(host, &a, sizeof a);
    socklen_t len = sizeof a;
    getsockname(host, &a, &len);
    if (unshare(CLONE_NEWNET) != 0)
        return printf("unshare: %d\n", errno), 1;
    int ctl = socket(AF_INET, SOCK_DGRAM, 0);
    struct {
        char name[16];
        short flags;
        char pad[22];
    } ifr;
    memset(&ifr, 0, sizeof ifr);
    ifr.name[0] = 'l';
    ifr.name[1] = 'o';
    ifr.flags = IFF_UP;
    if (ioctl(ctl, SIOCSIFFLAGS, &ifr) != 0)
        return printf("lo up: %d\n", errno), 1;
    int u = socket(AF_INET, SOCK_DGRAM, 0);
    long sent = sendto(u, "leak", 4, 0, &a, sizeof a);
    int c = socket(AF_INET, SOCK_DGRAM, 0);
    int conn = connect(c, &a, sizeof a);
    struct sockaddr_in peer;
    socklen_t plen = sizeof peer;
    getpeername(c, &peer, &plen);
    int named = peer.sin_port == a.sin_port;
    long first = send(c, "leak", 4, 0);
    usleep(50000);
    char b[8];
    long refused = recv(c, b, sizeof b, MSG_DONTWAIT);
    int refused_errno = errno;
    long leaked = recv(host, b, sizeof b, MSG_DONTWAIT);
    printf("sent %ld, connected %d named %d, sent %ld, then %ld errno %d, host got %ld\n", sent,
           conn, named, first, refused, refused_errno, leaked);

    /* A server bound in the namespace answers a client that never bound. */
    int server = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in s = loopback(5353);
    bind(server, &s, sizeof s);
    int client = socket(AF_INET, SOCK_DGRAM, 0);
    sendto(client, "ping", 4, 0, &s, sizeof s);
    struct sockaddr_in from;
    socklen_t flen = sizeof from;
    long got = recvfrom(server, b, sizeof b, 0, &from, &flen);
    sendto(server, "pong", 4, 0, &from, flen);
    long back = recv(client, b, sizeof b, 0);
    printf("served %ld, answered %ld\n", got, back);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2)
        return 2;
    if (!strcmp(argv[1], "pinned"))
        return pinned();
    if (!strcmp(argv[1], "unbound"))
        return unbound();
    return 2;
}
