/* Multicast membership on TCP sockets, as Linux answers it: no group is
 * joined with IP_ADD_MEMBERSHIP or IPV6_ADD_MEMBERSHIP (EPROTO), but the
 * source and protocol-independent options join and leave, each group once.
 * Each step prints its errno (0 for success). */
int socket(int domain, int type, int protocol);
int setsockopt(int fd, int level, int name, const void *val, unsigned len);
int close(int fd);
int printf(const char *fmt, ...);
void *memset(void *d, int c, unsigned long n);
int *__errno_location(void);

static void step(const char *what, int fd, int level, int name, const void *v, unsigned len) {
    int r = setsockopt(fd, level, name, v, len);
    printf("%s: %d\n", what, r ? *__errno_location() : 0);
}

#define GROUP4 0xfb0000e0u  /* 224.0.0.251 */
#define LO4 0x0100007fu     /* 127.0.0.1 */
#define SRC4 0x0100000au    /* 10.0.0.1 */

/* group_req or group_source_req for IPv4 group `g` (and source `s`) on
 * interface 1 (lo). */
static void greq4(unsigned char *b, unsigned g, unsigned s) {
    memset(b, 0, 264);
    b[0] = 1;
    b[8] = 2;
    *(unsigned *)(b + 12) = g;
    b[136] = 2;
    *(unsigned *)(b + 140) = s;
}

static void greq6(unsigned char *b) {
    memset(b, 0, 264);
    b[0] = 1;
    b[8] = 10;
    b[16] = 0xff;
    b[17] = 0x02;
    b[31] = 0xfb;
}

int main(void) {
    int t = socket(2, 1, 0);
    unsigned mreq[3] = {GROUP4, LO4, SRC4};
    unsigned char b[264];
    step("IP_ADD_MEMBERSHIP", t, 0, 35, mreq, 8);
    step("IP_ADD_MEMBERSHIP, no room", t, 0, 35, mreq, 0);
    step("IP_DROP_MEMBERSHIP", t, 0, 36, mreq, 8);
    step("IP_ADD_SOURCE_MEMBERSHIP", t, 0, 39, mreq, 12);
    step("IP_ADD_SOURCE_MEMBERSHIP again", t, 0, 39, mreq, 12);
    step("IP_DROP_SOURCE_MEMBERSHIP", t, 0, 40, mreq, 12);
    step("IP_DROP_SOURCE_MEMBERSHIP again", t, 0, 40, mreq, 12);
    greq4(b, GROUP4, SRC4);
    step("MCAST_JOIN_GROUP", t, 0, 42, b, 136);
    step("MCAST_JOIN_GROUP again", t, 0, 42, b, 136);
    step("MCAST_LEAVE_GROUP", t, 0, 45, b, 136);
    step("MCAST_LEAVE_GROUP again", t, 0, 45, b, 136);
    step("MCAST_JOIN_SOURCE_GROUP", t, 0, 46, b, 264);
    step("MCAST_LEAVE_SOURCE_GROUP", t, 0, 47, b, 264);
    step("MCAST_LEAVE_SOURCE_GROUP again", t, 0, 47, b, 264);
    /* Sources blocked in a group joined from any. */
    step("MCAST_JOIN_GROUP for blocks", t, 0, 42, b, 136);
    step("MCAST_BLOCK_SOURCE", t, 0, 43, b, 264);
    step("MCAST_BLOCK_SOURCE again", t, 0, 43, b, 264);
    step("MCAST_JOIN_SOURCE_GROUP with sources blocked", t, 0, 46, b, 264);
    step("MCAST_UNBLOCK_SOURCE", t, 0, 44, b, 264);
    step("MCAST_UNBLOCK_SOURCE again", t, 0, 44, b, 264);
    for (unsigned i = 1; i <= 11; i++) {
        greq4(b, GROUP4, SRC4 + (i << 24));
        int r = setsockopt(t, 0, 43, b, 264);
        if (r) printf("MCAST_BLOCK_SOURCE number %u: %d\n", i, *__errno_location());
    }
    /* A filter: include mode, one source; its source taken leaves. */
    unsigned char f[272];
    memset(f, 0, sizeof f);
    f[0] = 1;
    f[8] = 2;
    *(unsigned *)(f + 12) = GROUP4;
    *(unsigned *)(f + 136) = 1;   /* MCAST_INCLUDE */
    *(unsigned *)(f + 140) = 1;   /* one source */
    f[144] = 2;
    *(unsigned *)(f + 148) = SRC4;
    step("MCAST_MSFILTER include one", t, 0, 48, f, 272);
    greq4(b, GROUP4, SRC4);
    step("MCAST_LEAVE_SOURCE_GROUP its source", t, 0, 47, b, 264);
    step("MCAST_LEAVE_GROUP after", t, 0, 45, b, 136);
    step("MCAST_MSFILTER not joined", t, 0, 48, f, 272);
    *(unsigned *)(f + 136) = 5;
    step("MCAST_MSFILTER mode 5", t, 0, 48, f, 272);
    unsigned msf[5] = {GROUP4, LO4, 0, 0, 0};
    step("IP_MSFILTER not joined", t, 0, 41, msf, 16);
    step("IP_MSFILTER short", t, 0, 41, msf, 12);
    step("IP_BLOCK_SOURCE not joined", t, 0, 38, mreq, 12);
    step("IP_ADD_SOURCE_MEMBERSHIP short", t, 0, 39, mreq, 8);
    /* Addresses of another family, or not multicast. */
    greq4(b, GROUP4, SRC4);
    b[8] = 10;
    step("MCAST_JOIN_GROUP of an IPv6 address", t, 0, 42, b, 136);
    step("MCAST_JOIN_SOURCE_GROUP of an IPv6 address", t, 0, 46, b, 264);
    greq4(b, LO4, SRC4);
    step("MCAST_JOIN_GROUP of 127.0.0.1", t, 0, 42, b, 136);
    step("MCAST_LEAVE_GROUP of 127.0.0.1", t, 0, 45, b, 136);
    step("MCAST_JOIN_GROUP short", t, 0, 42, b, 100);
    close(t);

    int t6 = socket(10, 1, 0);
    unsigned char m6[20] = {0xff, 0x02, [15] = 0xfb, [16] = 1};
    step("IPV6_ADD_MEMBERSHIP", t6, 41, 20, m6, 20);
    step("IPV6_ADD_MEMBERSHIP, no room", t6, 41, 20, m6, 0);
    step("IPV6_DROP_MEMBERSHIP", t6, 41, 21, m6, 20);
    greq6(b);
    step("IPv6 MCAST_JOIN_GROUP", t6, 41, 42, b, 136);
    step("IPv6 MCAST_JOIN_GROUP again", t6, 41, 42, b, 136);
    step("IPv6 MCAST_LEAVE_GROUP", t6, 41, 45, b, 136);
    step("IPv6 MCAST_LEAVE_GROUP again", t6, 41, 45, b, 136);
    b[8] = 2;
    step("IPv6 MCAST_JOIN_GROUP of an IPv4 address", t6, 41, 42, b, 136);
    greq6(b);
    b[16] = 0xfe;
    step("IPv6 MCAST_LEAVE_GROUP of fe02::fb", t6, 41, 45, b, 136);
    /* IPv4 groups on an IPv6 socket. */
    greq4(b, GROUP4, SRC4);
    step("MCAST_JOIN_GROUP on an IPv6 socket", t6, 0, 42, b, 136);
    close(t6);
    return 0;
}
