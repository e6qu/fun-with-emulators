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

int main(int argc, char **argv) {
    if (argc < 2)
        return 2;
    if (!strcmp(argv[1], "pinned"))
        return pinned();
    return 2;
}
