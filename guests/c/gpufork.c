/* A fork after the GPU's device is in use: the child's copy of its
 * parent's open of the device fails its calls (ENODEV: its context is the
 * parent's renderer's), an open of its own has a context of its own, and
 * the parent, whose open goes on working, waits for the child and for
 * nothing else (no process of the renderer's is its child to see).
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

typedef unsigned long u64;
typedef unsigned int u32;

int open(const char *path, int flags, ...);
int ioctl(int fd, unsigned long request, ...);
int fork(void);
int waitpid(int pid, int *status, int options);
int *__errno_location(void);
int printf(const char *format, ...);
int fflush(void *stream);
void _exit(int status);

#define O_RDWR 02
#define O_CLOEXEC 02000000
#define ENODEV 19
#define ECHILD 10
#define WNOHANG 1

/* _IOWR('d', nr, size) */
#define IOWR(nr, size) ((3ul << 30) | ((unsigned long)(size) << 16) | ('d' << 8) | (nr))
#define DRM_IOCTL_VERSION IOWR(0x00, 64)
#define VIRTGPU_GETPARAM IOWR(0x43, 16)
#define VIRTGPU_CONTEXT_INIT IOWR(0x4b, 16)

struct version {
    int major, minor, patch;
    u64 name_len;
    char *name;
    u64 date_len;
    char *date;
    u64 desc_len;
    char *desc;
};

/* The driver's name, or -1 with errno. */
static int driver(int fd, char name[32]) {
    struct version v = {0};
    v.name_len = 31;
    v.name = name;
    for (int i = 0; i < 32; i++) {
        name[i] = 0;
    }
    return ioctl(fd, DRM_IOCTL_VERSION, &v);
}

/* A Venus context of one ring on `fd`. */
static int context(int fd) {
    u64 params[4] = {1 /* CAPSET_ID */, 4 /* Venus */, 2 /* NUM_RINGS */, 1};
    struct {
        u32 count, pad;
        u64 params;
    } init = {2, 0, (u64)params};
    return ioctl(fd, VIRTGPU_CONTEXT_INIT, &init);
}

static int three_d(int fd) {
    int value = 0;
    u64 p[2] = {1 /* 3D_FEATURES */, (u64)&value};
    return ioctl(fd, VIRTGPU_GETPARAM, p) == 0 ? value : -1;
}

static int is(const char *a, const char *b) {
    while (*a && *a == *b) {
        a++, b++;
    }
    return *a == *b;
}

int main(void) {
    char name[32];
    int fd = open("/dev/dri/renderD128", O_RDWR | O_CLOEXEC);
    if (fd < 0 || driver(fd, name) != 0 || !is(name, "virtio_gpu") || context(fd) != 0) {
        printf("parent: no device (errno %d)\n", *__errno_location());
        return 1;
    }
    fflush(0);
    int pid = fork();
    if (pid < 0) {
        return 1;
    }
    if (pid == 0) {
        int inherited = driver(fd, name) == 0 ? 0 : *__errno_location();
        int own = open("/dev/dri/renderD128", O_RDWR | O_CLOEXEC);
        int ok = own >= 0 && driver(own, name) == 0 && is(name, "virtio_gpu") && context(own) == 0;
        printf("child: inherited open %s, own open %s\n",
               inherited == ENODEV ? "ENODEV" : "not ENODEV", ok ? "has a context" : "failed");
        fflush(0);
        _exit(0);
    }
    int status = -1;
    int waited = waitpid(-1, &status, 0);
    int more = waitpid(-1, &status, WNOHANG);
    int none = more < 0 && *__errno_location() == ECHILD;
    printf("parent: waited for %s, then %s; its open %s\n",
           waited == pid ? "the child" : "another", none ? "no child" : "another",
           three_d(fd) == 1 ? "works" : "failed");
    return 0;
}
