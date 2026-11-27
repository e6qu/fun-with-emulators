/* What fwe keeps of a socket that macOS has no place for is the socket's,
 * as on Linux, so a dup of it shares it: a multicast group a TCP socket
 * joined with a source (Linux allows it, macOS refuses), and the IPv4 view
 * IPV6_ADDRFORM gives an IPv6 socket. */
struct sockaddr_in { unsigned short family, port; unsigned addr; char zero[8]; };
struct sockaddr_in6 {
    unsigned short family, port; unsigned flow; unsigned char addr[16]; unsigned scope;
};
int socket(int domain, int type, int protocol);
int bind(int fd, const void *a, unsigned len);
int listen(int fd, int n);
int connect(int fd, const void *a, unsigned len);
int getsockname(int fd, void *a, unsigned *len);
int setsockopt(int fd, int level, int name, const void *val, unsigned len);
int dup(int fd);
int close(int fd);
int printf(const char *fmt, ...);
int *__errno_location(void);
#define errno (*__errno_location())

static const char *res(int r) {
    if (r == 0) return "0";
    switch (errno) {
    case 98: return "EADDRINUSE";
    case 99: return "EADDRNOTAVAIL";
    case 19: return "ENODEV";
    default: {
        static char b[16];
        int e = errno, i = 15;
        b[i] = 0;
        do { b[--i] = '0' + e % 10; e /= 10; } while (e && i > 6);
        b[--i] = ' ';
        b[--i] = 'o'; b[--i] = 'n'; b[--i] = 'r'; b[--i] = 'r'; b[--i] = 'e';
        return b + i;
    }
    }
}

int main(void) {
    /* A group joined through one descriptor, left through the other. */
    int t = socket(2, 1, 0);
    /* 224.0.0.251 on the loopback interface, from 10.0.0.1. */
    unsigned mreq[3] = {0xfb0000e0, 0x0100007f, 0x0100000a};
    int d = dup(t);
    /* IP_ADD_SOURCE_MEMBERSHIP, IP_DROP_SOURCE_MEMBERSHIP */
    printf("join: %s\n", res(setsockopt(t, 0, 39, mreq, 12)));
    printf("join again through a dup: %s\n", res(setsockopt(d, 0, 39, mreq, 12)));
    printf("leave through the dup: %s\n", res(setsockopt(d, 0, 40, mreq, 12)));
    printf("leave again through the socket: %s\n", res(setsockopt(t, 0, 40, mreq, 12)));
    close(t);
    close(d);

    /* An IPv6 socket connected to an IPv4 peer, made IPv4. */
    int l = socket(2, 1, 0);
    struct sockaddr_in a = {2, 0, 0x0100007f, {0}};
    unsigned len = sizeof a;
    bind(l, &a, sizeof a);
    listen(l, 1);
    getsockname(l, &a, &len);
    int s = socket(10, 1, 0);
    struct sockaddr_in6 b = {10, a.port, 0, {0}, 0};
    b.addr[10] = b.addr[11] = 0xff;
    b.addr[12] = 127;
    b.addr[15] = 1;
    connect(s, &b, sizeof b);
    int dd = dup(s);
    int inet = 2;
    printf("IPV6_ADDRFORM: %s\n", res(setsockopt(s, 41, 1, &inet, sizeof inet)));
    struct sockaddr_in6 n;
    len = sizeof n;
    getsockname(dd, &n, &len);
    printf("the dup's name: family %d, %u bytes\n", n.family, len);
    return 0;
}
