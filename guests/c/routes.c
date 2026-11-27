/* A network namespace's routes, as netlink (RTM_GETROUTE) and /proc/net
 * show them: in a new namespace none until lo is up, then lo's local ones
 * (GLib's network monitor and `ip route` dump them); a route found for an
 * address; and in the initial namespace, a main table whose routes'
 * interfaces exist. */
int printf(const char *fmt, ...);
int socket(int domain, int type, int protocol);
long send(int fd, const void *buf, unsigned long n, int flags);
long recv(int fd, void *buf, unsigned long n, int flags);
int close(int fd);
int open(const char *path, int flags, ...);
long read(int fd, void *buf, unsigned long n);
int unshare(int flags);
int fork(void);
int waitpid(int pid, int *status, int options);
void *memset(void *p, int c, unsigned long n);
void *memcpy(void *d, const void *s, unsigned long n);
char *strchr(const char *s, int c);
int fflush(void *f);
void _exit(int status);

#define AF_NETLINK 16
#define SOCK_RAW 3
#define NETLINK_ROUTE 0
#define RTM_NEWLINK 16
#define RTM_NEWROUTE 24
#define RTM_GETROUTE 26
#define NLM_F_REQUEST 1
#define NLM_F_ACK 4
#define NLM_F_DUMP 0x300
#define NLMSG_ERROR 2
#define NLMSG_DONE 3
#define CLONE_NEWNET 0x40000000
#define CLONE_NEWUSER 0x10000000
#define RTA_DST 1
#define RTA_OIF 4
#define RTA_PREFSRC 7

struct nlmsghdr { unsigned len; unsigned short type, flags; unsigned seq, pid; };
struct rtmsg {
    unsigned char family, dst_len, src_len, tos, table, protocol, scope, type;
    unsigned flags;
};
struct ifinfomsg { unsigned char family, pad; unsigned short type; int index; unsigned flags, change; };

static char buf[65536];

static const char *kind(int t) {
    static const char *names[] = {"unspec", "unicast", "local", "broadcast", "anycast", "multicast"};
    return t < 6 ? names[t] : "other";
}

static const char *table(int t) { return t == 254 ? "main" : t == 255 ? "local" : "other"; }

/* `a` (`n` bytes) as an address: dotted, or ::1 and the like by hand. */
static void addr(const unsigned char *a, int n) {
    if (n == 4) {
        printf("%d.%d.%d.%d", a[0], a[1], a[2], a[3]);
        return;
    }
    int zero = 1;
    for (int i = 0; i < 15; i++) zero &= a[i] == 0;
    if (zero) printf("::%x", a[15]);
    else printf("%02x%02x::", a[0], a[1]);
}

/* Each route of a dump, or the one route found, printed; the error, if one. */
static int show(int fd, int all, int *main_routes, int *bad_oif) {
    for (;;) {
        long n = recv(fd, buf, sizeof buf, 0);
        if (n <= 0) return -1;
        for (long at = 0; at + 16 <= n;) {
            struct nlmsghdr *h = (struct nlmsghdr *)(buf + at);
            if (h->type == NLMSG_DONE) return 0;
            if (h->type == NLMSG_ERROR) return *(int *)(h + 1);
            struct rtmsg *r = (struct rtmsg *)(h + 1);
            const unsigned char *dst = 0;
            unsigned oif = 0;
            for (unsigned a = 16 + 12; a + 4 <= h->len;) {
                unsigned short len = *(unsigned short *)((char *)h + a);
                unsigned short ty = *(unsigned short *)((char *)h + a + 2);
                if (ty == RTA_DST) dst = (const unsigned char *)h + a + 4;
                if (ty == RTA_OIF) memcpy(&oif, (char *)h + a + 4, 4);
                a += (len + 3) & ~3u;
            }
            if (main_routes) {
                if (r->table == 254) {
                    (*main_routes)++;
                    if (oif == 0) (*bad_oif)++;
                }
            } else {
                printf("  %s table %s ", kind(r->type), table(r->table));
                if (dst) addr(dst, r->family == 2 ? 4 : 16);
                else printf("default");
                printf("/%d scope %d oif %u%s\n", r->dst_len, r->scope, oif,
                       r->flags & 0x200 ? " cached" : "");
            }
            if (!all) return 0;
            at += (h->len + 3) & ~3u;
        }
    }
}

static int request(int fd, int type, int flags, int family, const void *dst, int dst_n) {
    char req[64];
    memset(req, 0, sizeof req);
    struct nlmsghdr *h = (struct nlmsghdr *)req;
    struct rtmsg *r = (struct rtmsg *)(h + 1);
    r->family = family;
    unsigned len = 16 + 12;
    if (dst) {
        *(unsigned short *)(req + len) = 4 + dst_n;
        *(unsigned short *)(req + len + 2) = RTA_DST;
        memcpy(req + len + 4, dst, dst_n);
        len += (4 + dst_n + 3) & ~3u;
        r->dst_len = dst_n * 8;
    }
    h->len = len;
    h->type = type;
    h->flags = NLM_F_REQUEST | flags;
    h->seq = 1;
    return send(fd, req, len, 0) == len ? 0 : -1;
}

static void lo_up(int fd) {
    char req[64];
    memset(req, 0, sizeof req);
    struct nlmsghdr *h = (struct nlmsghdr *)req;
    struct ifinfomsg *i = (struct ifinfomsg *)(h + 1);
    i->index = 1;
    i->flags = 1;
    i->change = 1;
    h->len = 16 + sizeof *i;
    h->type = RTM_NEWLINK;
    h->flags = NLM_F_REQUEST | NLM_F_ACK;
    send(fd, req, h->len, 0);
    recv(fd, buf, sizeof buf, 0);
}

/* /proc/net/route's lines and whether each is 127 characters wide, and
 * ipv6_route's lines. */
static void proc_files(void) {
    int fd = open("/proc/net/route", 0);
    long n = read(fd, buf, sizeof buf - 1);
    close(fd);
    buf[n > 0 ? n : 0] = 0;
    int lines = 0, wide = 1;
    for (char *p = buf; *p;) {
        char *nl = strchr(p, '\n');
        if (!nl) break;
        wide &= nl - p == 127;
        lines++;
        p = nl + 1;
    }
    printf("  /proc/net/route: %d lines, padded: %s\n", lines, wide ? "yes" : "no");
    fd = open("/proc/net/ipv6_route", 0);
    n = read(fd, buf, sizeof buf - 1);
    close(fd);
    buf[n > 0 ? n : 0] = 0;
    lines = 0;
    for (char *p = buf; (p = strchr(p, '\n')) != 0; p++) lines++;
    printf("  /proc/net/ipv6_route: %d lines\n", lines);
}

int main(void) {
    /* The initial namespace: a main table, each route on an interface. */
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    request(fd, RTM_GETROUTE, NLM_F_DUMP, 0, 0, 0);
    int main_routes = 0, bad = 0;
    int e = show(fd, 1, &main_routes, &bad);
    printf("host: dump %d, main routes: %s, each on an interface: %s\n", e,
           main_routes > 0 ? "yes" : "no", bad ? "no" : "yes");
    close(fd);
    fflush(0);
    int pid = fork();
    if (pid == 0) {
        if (unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0) _exit(1);
        fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
        printf("new namespace, lo down:\n");
        request(fd, RTM_GETROUTE, NLM_F_DUMP, 0, 0, 0);
        printf("  dump: %d\n", show(fd, 1, 0, 0));
        proc_files();
        lo_up(fd);
        printf("lo up:\n");
        request(fd, RTM_GETROUTE, NLM_F_DUMP, 0, 0, 0);
        printf("  dump: %d\n", show(fd, 1, 0, 0));
        printf("IPv6 alone:\n");
        request(fd, RTM_GETROUTE, NLM_F_DUMP, 10, 0, 0);
        printf("  dump: %d\n", show(fd, 1, 0, 0));
        proc_files();
        unsigned char lo[4] = {127, 0, 0, 1}, far[4] = {8, 8, 8, 8};
        printf("get 127.0.0.1:\n");
        request(fd, RTM_GETROUTE, 0, 2, lo, 4);
        printf("  error: %d\n", show(fd, 0, 0, 0));
        printf("get 8.8.8.8:\n");
        request(fd, RTM_GETROUTE, 0, 2, far, 4);
        printf("  error: %d\n", show(fd, 0, 0, 0));
        fflush(0);
        _exit(0);
    }
    int status;
    waitpid(pid, &status, 0);
    printf("child: %d\n", status);
    return 0;
}
