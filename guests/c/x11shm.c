/* An X client of its own (the protocol written by hand, no libraries)
 * drawing through MIT-SHM: it connects to the display DISPLAY names by its
 * Unix socket (/tmp/.X11-unix/X<n>), makes a pixmap, fills a System V
 * shared memory segment with a pattern and has the server copy it into
 * the pixmap (ShmAttach, ShmPutImage), then reads the pixmap back
 * (GetImage); then has the server fill a rectangle of it and copy that
 * into the segment (ShmGetImage), and reads the segment. Each line says
 * what came back. With "fork", a fork child does it. */
#include <stddef.h>
#include <stdint.h>

int printf(const char *fmt, ...);
char *getenv(const char *name);
int socket(int domain, int type, int protocol);
int connect(int fd, const void *addr, unsigned len);
long write(int fd, const void *buf, unsigned long n);
long read(int fd, void *buf, unsigned long n);
int shmget(int key, unsigned long size, int flags);
void *shmat(int id, const void *addr, int flags);
int shmctl(int id, int cmd, void *buf);
void *memset(void *d, int c, unsigned long n);
void *memcpy(void *d, const void *s, unsigned long n);
unsigned long strlen(const char *s);
int fork(void);
int waitpid(int pid, int *status, int options);

#define W 64
#define H 32
#define IPC_PRIVATE 0
#define IPC_CREAT 01000
#define IPC_RMID 0

static int fd;
static uint8_t buf[1 << 16];
static uint32_t next_id;

static void put(const void *p, unsigned long n) {
    const uint8_t *b = p;
    while (n > 0) {
        long r = write(fd, b, n);
        if (r <= 0) {
            printf("write failed\n");
            return;
        }
        b += r;
        n -= (unsigned long)r;
    }
}

static int get(void *p, unsigned long n) {
    uint8_t *b = p;
    while (n > 0) {
        long r = read(fd, b, n);
        if (r <= 0) return -1;
        b += r;
        n -= (unsigned long)r;
    }
    return 0;
}

static uint16_t u16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t u32(const uint8_t *p) { return p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24; }

/* The next reply (its 32 bytes, then its extra data into buf + 32), an
 * error said and -1 instead; events are skipped. */
static int reply(void) {
    for (;;) {
        if (get(buf, 32) < 0) {
            printf("connection closed\n");
            return -1;
        }
        if (buf[0] == 0) {
            printf("X error %u (request %u.%u)\n", buf[1], buf[10], u16(buf + 8));
            return -1;
        }
        if (buf[0] == 1) {
            uint32_t more = 4 * u32(buf + 4);
            if (more > sizeof buf - 32 || get(buf + 32, more) < 0) return -1;
            return 0;
        }
    }
}

struct req {
    uint8_t b[64];
    unsigned n;
};
static void r8(struct req *r, uint8_t v) { r->b[r->n++] = v; }
static void r16(struct req *r, uint16_t v) { r8(r, v & 0xff); r8(r, v >> 8); }
static void r32(struct req *r, uint32_t v) { r16(r, v & 0xffff); r16(r, v >> 16); }
static void send_req(struct req *r) {
    r->b[2] = (uint8_t)(r->n / 4);
    r->b[3] = (uint8_t)((r->n / 4) >> 8);
    put(r->b, r->n);
}
static struct req start(uint8_t major, uint8_t data) {
    struct req r = {{0}, 0};
    r8(&r, major);
    r8(&r, data);
    r16(&r, 0);
    return r;
}

static int draw(void);

/* With "fork", from a fork child, its parent waiting for it. */
int main(int argc, char **argv) {
    if (argc > 1 && argv[1][0] == 'f') {
        int pid = fork();
        if (pid == 0) return draw();
        int status = 0;
        if (waitpid(pid, &status, 0) != pid) return 1;
        return (status >> 8) & 0xff;
    }
    return draw();
}

static int draw(void) {
    const char *display = getenv("DISPLAY");
    if (!display || display[0] != ':') {
        printf("DISPLAY is not :<n>\n");
        return 1;
    }
    struct {
        uint16_t family;
        char path[108];
    } addr = {1, {0}};
    const char *dir = "/tmp/.X11-unix/X";
    unsigned long d = strlen(dir), i = 0;
    memcpy(addr.path, dir, d);
    for (const char *p = display + 1; *p && *p != '.'; p++) addr.path[d + i++] = *p;
    fd = socket(1, 1, 0);
    if (connect(fd, &addr, sizeof addr) != 0) {
        printf("cannot connect to %s\n", addr.path);
        return 1;
    }
    /* The setup, with no authorization. */
    uint8_t setup[12] = {'l', 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    put(setup, 12);
    if (get(buf, 8) < 0 || buf[0] != 1) {
        printf("setup refused\n");
        return 1;
    }
    uint32_t more = 4 * u16(buf + 6);
    if (get(buf + 8, more) < 0) return 1;
    uint32_t id_base = u32(buf + 12);
    uint16_t vendor = u16(buf + 24);
    uint8_t formats = buf[29];
    const uint8_t *screen = buf + 40 + ((vendor + 3) & ~3u) + 8 * formats;
    uint32_t root = u32(screen);
    uint8_t depth = screen[38];
    next_id = id_base;
    printf("connected: depth %u\n", depth);

    /* QueryExtension("MIT-SHM"). */
    struct req q = start(98, 0);
    r16(&q, 7);
    r16(&q, 0);
    memcpy(q.b + q.n, "MIT-SHM\0", 8);
    q.n += 8;
    send_req(&q);
    if (reply() < 0 || !buf[8]) {
        printf("no MIT-SHM\n");
        return 1;
    }
    uint8_t shm = buf[9];

    uint32_t pixmap = next_id++, gc = next_id++, seg = next_id++;
    struct req r = start(53, depth); /* CreatePixmap */
    r32(&r, pixmap);
    r32(&r, root);
    r16(&r, W);
    r16(&r, H);
    send_req(&r);
    r = start(55, 0); /* CreateGC */
    r32(&r, gc);
    r32(&r, pixmap);
    r32(&r, 0);
    send_req(&r);

    int id = shmget(IPC_PRIVATE, W * H * 4, IPC_CREAT | 0600);
    uint32_t *pixels = shmat(id, 0, 0);
    if (id < 0 || pixels == (void *)-1) {
        printf("no shared memory\n");
        return 1;
    }
    for (uint32_t k = 0; k < W * H; k++) pixels[k] = (k * 2654435761u) & 0xffffff;

    r = start(shm, 1); /* ShmAttach */
    r32(&r, seg);
    r32(&r, (uint32_t)id);
    r8(&r, 0);
    r8(&r, 0);
    r16(&r, 0);
    send_req(&r);
    r = start(shm, 3); /* ShmPutImage */
    r32(&r, pixmap);
    r32(&r, gc);
    r16(&r, W);
    r16(&r, H);
    r16(&r, 0);
    r16(&r, 0);
    r16(&r, W);
    r16(&r, H);
    r16(&r, 0);
    r16(&r, 0);
    r8(&r, depth);
    r8(&r, 2);
    r8(&r, 0);
    r8(&r, 0);
    r32(&r, seg);
    r32(&r, 0);
    send_req(&r);
    r = start(73, 2); /* GetImage, ZPixmap */
    r32(&r, pixmap);
    r16(&r, 0);
    r16(&r, 0);
    r16(&r, W);
    r16(&r, H);
    r32(&r, 0xffffffff);
    send_req(&r);
    if (reply() < 0) return 1;
    int same = 1;
    for (uint32_t k = 0; k < W * H; k++)
        if ((u32(buf + 32 + 4 * k) & 0xffffff) != pixels[k]) same = 0;
    printf("put through shared memory: %s\n", same ? "drawn" : "different");

    /* The server writes the segment: a rectangle filled, then copied in. */
    r = start(56, 0); /* ChangeGC: foreground */
    r32(&r, gc);
    r32(&r, 4);
    r32(&r, 0x123456);
    send_req(&r);
    r = start(70, 0); /* PolyFillRectangle */
    r32(&r, pixmap);
    r32(&r, gc);
    r16(&r, 0);
    r16(&r, 0);
    r16(&r, W);
    r16(&r, H);
    send_req(&r);
    r = start(shm, 4); /* ShmGetImage, ZPixmap */
    r32(&r, pixmap);
    r16(&r, 0);
    r16(&r, 0);
    r16(&r, W);
    r16(&r, H);
    r32(&r, 0xffffffff);
    r8(&r, 2);
    r8(&r, 0);
    r8(&r, 0);
    r8(&r, 0);
    r32(&r, seg);
    r32(&r, 0);
    send_req(&r);
    if (reply() < 0) return 1;
    int filled = 1;
    for (uint32_t k = 0; k < W * H; k++)
        if ((pixels[k] & 0xffffff) != 0x123456) filled = 0;
    printf("got through shared memory: %s\n", filled ? "filled" : "different");
    shmctl(id, IPC_RMID, 0);
    return 0;
}
