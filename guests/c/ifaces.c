/* Network interfaces seen one way: netlink (what getifaddrs reads) and
 * the interface requests agree, in the initial network namespace (the
 * host's interfaces) and in a new one (lo, its MTU as set).
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

typedef unsigned long size_t;

struct sockaddr {
    unsigned short sa_family;
    char sa_data[14];
};
struct sockaddr_in {
    unsigned short sin_family;
    unsigned short sin_port;
    unsigned sin_addr;
    unsigned char zero[8];
};
struct ifaddrs {
    struct ifaddrs *ifa_next;
    char *ifa_name;
    unsigned ifa_flags;
    struct sockaddr *ifa_addr;
    struct sockaddr *ifa_netmask;
    struct sockaddr *ifa_ifu;
    void *ifa_data;
};
struct ifreq {
    char name[16];
    union {
        struct sockaddr addr;
        int mtu;
        short flags;
        char pad[24];
    } u;
};
struct ifconf {
    int len;
    struct ifreq *req;
};

int getifaddrs(struct ifaddrs **list);
void freeifaddrs(struct ifaddrs *list);
int socket(int domain, int type, int protocol);
int ioctl(int fd, unsigned long req, ...);
int unshare(int flags);
long send(int fd, const void *buf, size_t n, int flags);
long recv(int fd, void *buf, size_t n, int flags);
int strcmp(const char *a, const char *b);
int printf(const char *format, ...);
void *memset(void *s, int c, size_t n);
int *__errno_location(void);

#define AF_INET 2
#define AF_NETLINK 16
#define SOCK_DGRAM 2
#define SOCK_RAW 3
#define CLONE_NEWNET 0x40000000
#define SIOCGIFCONF 0x8912
#define SIOCSIFFLAGS 0x8914
#define SIOCSIFMTU 0x8922
#define IFF_UP 1

/* Every IPv4 address getifaddrs lists is one SIOCGIFCONF lists, on the
 * same interface, and the other way round. */
static int same_addresses(void) {
    static struct ifreq reqs[64];
    struct ifconf conf = {sizeof reqs, reqs};
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (ioctl(s, SIOCGIFCONF, &conf) != 0)
        return printf("SIOCGIFCONF failed\n"), 0;
    int n = conf.len / (int)sizeof(struct ifreq);
    struct ifaddrs *list;
    if (getifaddrs(&list) != 0)
        return printf("getifaddrs failed\n"), 0;
    int listed = 0, matched = 0, lo = 0;
    for (struct ifaddrs *i = list; i; i = i->ifa_next) {
        if (!i->ifa_addr || i->ifa_addr->sa_family != AF_INET)
            continue;
        listed++;
        unsigned a = ((struct sockaddr_in *)i->ifa_addr)->sin_addr;
        lo |= !strcmp(i->ifa_name, "lo") && a == 0x0100007f;
        for (int k = 0; k < n; k++)
            if (!strcmp(reqs[k].name, i->ifa_name) &&
                ((struct sockaddr_in *)&reqs[k].u.addr)->sin_addr == a) {
                matched++;
                break;
            }
    }
    freeifaddrs(list);
    return listed == n && matched == n && lo;
}

/* The MTU netlink reports for interface 1. */
static unsigned netlink_mtu(void) {
    int s = socket(AF_NETLINK, SOCK_RAW, 0);
    struct {
        unsigned len;
        unsigned short type, flags;
        unsigned seq, pid;
        unsigned char family, pad;
        unsigned short type2;
        int index;
        unsigned flags2, change;
    } req = {32, 18, 1, 1, 0, 0, 0, 0, 1, 0, 0};
    send(s, &req, sizeof req, 0);
    unsigned char b[4096];
    long n = recv(s, b, sizeof b, 0);
    for (long at = 32; at + 4 <= n;) {
        unsigned short len = *(unsigned short *)(b + at), type = *(unsigned short *)(b + at + 2);
        if (len < 4)
            break;
        if (type == 4)
            return *(unsigned *)(b + at + 4);
        at += (len + 3) & ~3;
    }
    return 0;
}

int main(void) {
    printf("initial namespace agrees: %d\n", same_addresses());
    if (unshare(CLONE_NEWNET) != 0)
        return printf("unshare failed\n"), 1;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq r;
    memset(&r, 0, sizeof r);
    r.name[0] = 'l';
    r.name[1] = 'o';
    r.u.flags = IFF_UP;
    ioctl(s, SIOCSIFFLAGS, &r);
    r.u.mtu = 1280;
    ioctl(s, SIOCSIFMTU, &r);
    printf("new namespace agrees: %d, lo mtu %u\n", same_addresses(), netlink_mtu());
    return 0;
}
