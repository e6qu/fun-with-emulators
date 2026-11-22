/* Micro-benchmarks, built for Linux (run under fwe or on Linux) and for
 * macOS (run natively), from this one source:
 *
 *   bench syscall N      N getppid calls; prints nanoseconds per call
 *   bench getpid N       N getpid system calls (not a C library's cached
 *                        value); nanoseconds per call
 *   bench nr K N         N calls of system call number K, no arguments
 *   bench fork N         N fork + _exit + waitpid; prints microseconds each
 *   bench forkexec N P   N fork + execve(P) + waitpid; microseconds each
 *   bench thread N       N pthread_create + join; microseconds each
 *   bench par OP T N     T threads at once, each N calls of OP (getppid,
 *                        uname, or fstat of its own pipe); nanoseconds per
 *                        call per thread (the same for any T when calls
 *                        run in parallel)
 *   bench file OP N      N calls of OP on a file of 64 KiB in /tmp: pread
 *                        (4 KiB at offset 0), stat (of its path), open
 *                        (open + close), mmap (64 KiB anonymous, mapped and
 *                        unmapped); nanoseconds per call
 *   bench fault N        N loads through a null pointer, each a SIGSEGV
 *                        (or macOS's SIGBUS) its handler steps past, as a
 *                        JIT's implicit null checks are; microseconds each
 *   bench jit KIND N     the same machine code (`kernels` below) copied into
 *                        memory made executable at run time, as a JIT's
 *                        code is (fwe runs it by translation, macOS as it
 *                        is), run N rounds: `calls` (calls and returns,
 *                        fib 20 a round), `indirect` (a switch dispatched
 *                        through `br`, 12 a round), `pointers` (calls
 *                        through a register), `loop`, `functions` (4096
 *                        functions of 16 instructions called in a random
 *                        order: code larger than the instruction cache);
 *                        nanoseconds each; and `made` (N functions written
 *                        and each run once: making new code), microseconds
 *                        each
 *   bench x11 WHAT N     on the X display DISPLAY names (`:<n>`, by its
 *                        Unix socket), with the protocol written here:
 *                        `rtt`, N requests each waiting for its reply
 *                        (GetInputFocus), microseconds each; `shm`, N
 *                        frames of 512x512 written into a System V shared
 *                        memory segment and drawn into a window from it
 *                        (MIT-SHM's ShmPutImage), each waited for,
 *                        microseconds each for the drawing (the writing of
 *                        the pixels, the compiler's loop, not counted)
 *   bench ipc OP N       N rounds of OP, nanoseconds each: `sem` (a System
 *                        V semaphore raised and lowered), `msg` (a message
 *                        of 64 bytes sent and received), `shm` (a segment of
 *                        64 KiB made, attached, written, detached and
 *                        removed), and on Linux `eventfd` (written and
 *                        read) and `futex` (a process-shared wake, none
 *                        waiting, on memory mapped shared)
 *   bench exit           returns at once (for startup time)
 */
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#ifdef __APPLE__
#include <sys/ucontext.h>
#else
#include <ucontext.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <linux/futex.h>
#include <sys/eventfd.h>
#endif

static double now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e9 + ts.tv_nsec;
}

static void *nothing(void *arg) {
    return arg;
}

static long par_calls;
static const char *par_op;

static void *par(void *arg) {
    int fds[2];
    if (pipe(fds) != 0) {
        return NULL;
    }
    struct stat st;
    struct utsname u;
    volatile long sink = 0;
    for (long i = 0; i < par_calls; i++) {
        if (par_op[0] == 'f') {
            fstat(fds[0], &st);
        } else if (par_op[0] == 'u') {
            uname(&u);
        } else {
            sink += getppid();
        }
    }
    close(fds[0]);
    close(fds[1]);
    return arg;
}

static volatile long faults;

/* The `jit` benchmarks' machine code, made by clang from this assembly
 * (local labels only, so it runs wherever it is copied):
 *
 *   fib:    cmp x0, #2; b.lt 1f; stp x29, x30, [sp, #-32]!; mov x29, sp
 *           str x19, [sp, #16]; mov x19, x0; sub x0, x0, #1; bl fib
 *           sub x1, x19, #2; mov x19, x0; mov x0, x1; bl fib
 *           add x0, x0, x19; ldr x19, [sp, #16]; ldp x29, x30, [sp], #32
 *       1:  ret
 *   interp: (x0 bytecode, x1 rounds) mov x2, #0; mov x3, #0; mov x4, #0
 *           adr x5, 2f
 *       3:  ldrb w6, [x0, x3]; add x7, x5, x6, lsl #3; br x7
 *       2:  eight cases of two words each, on to 4f (the last to 5f):
 *           add x2, x2, #1 | eor x2, x2, #3 | lsl x2, x2, #1 |
 *           lsr x2, x2, #1 | sub x2, x2, #2 | orr x2, x2, #8 |
 *           and x2, x2, #0xffff | (b 5f; nop)
 *       4:  add x3, x3, #1; b 3b
 *       5:  add x4, x4, #1; mov x3, #0; cmp x4, x1; b.lt 3b; mov x0, x2; ret
 *   ptrs:   (x0 a table of 4 functions, x1 calls) a frame saving x19-x21;
 *           x0 = 0; for i < x1: blr table[i & 3] (and x9, x21, #3;
 *           ldr x9, [x19, x9, lsl #3]; blr x9); ret x0
 *   f0..f3: add x0, x0, #1 | eor x0, x0, #6 | add x0, x0, x0, lsl #1 |
 *           sub x0, x0, #7; each then ret
 *   loop:   (x0 n) v = 0; for i < n: v = v * 31 + i (madd); ret v
 *   driver: (x0 indexes as u32, x1 a table of functions, x2 calls) a
 *           frame saving x19-x22; x0 = x1 = 0, x2 = 1000; for each i:
 *           blr table[indexes[i]]; ret
 */
static const unsigned kernels[] = {
    0xf100081f, 0x540001cb, 0xa9be7bfd, 0x910003fd, 0xf9000bf3, 0xaa0003f3,
    0xd1000400, 0x97fffff9, 0xd1000a61, 0xaa0003f3, 0xaa0103e0, 0x97fffff5,
    0x8b130000, 0xf9400bf3, 0xa8c27bfd, 0xd65f03c0, 0xd2800002, 0xd2800003,
    0xd2800004, 0x10000085, 0x38636806, 0x8b060ca7, 0xd61f00e0, 0x91000442,
    0x1400000f, 0xd2400442, 0x1400000d, 0xd37ff842, 0x1400000b, 0xd341fc42,
    0x14000009, 0xd1000842, 0x14000007, 0xb27d0042, 0x14000005, 0x92403c42,
    0x14000003, 0x14000004, 0xd503201f, 0x91000463, 0x17ffffec, 0x91000484,
    0xd2800003, 0xeb01009f, 0x54fffd0b, 0xaa0203e0, 0xd65f03c0, 0xa9bd7bfd,
    0x910003fd, 0xa90153f3, 0xf90013f5, 0xaa0003f3, 0xaa0103f4, 0xd2800015,
    0xd2800000, 0x924006a9, 0xf8697a69, 0xd63f0120, 0x910006b5, 0xeb1402bf,
    0x54ffff6b, 0xa94153f3, 0xf94013f5, 0xa8c37bfd, 0xd65f03c0, 0x91000400,
    0xd65f03c0, 0xd27f0400, 0xd65f03c0, 0x8b000400, 0xd65f03c0, 0xd1001c00,
    0xd65f03c0, 0xd2800002, 0xd2800003, 0xd28003e4, 0x9b040c42, 0x91000463,
    0xeb00007f, 0x54ffffab, 0xaa0203e0, 0xd65f03c0, 0xa9bd7bfd, 0x910003fd,
    0xa90153f3, 0xa9025bf5, 0xaa0003f3, 0xaa0103f4, 0xaa0203f5, 0xd2800016,
    0xd2800000, 0xd2800001, 0xd2807d02, 0xb8767a69, 0xf8697a89, 0xd63f0120,
    0x910006d6, 0xeb1502df, 0x54ffff6b, 0xa94153f3, 0xa9425bf5, 0xa8c37bfd,
    0xd65f03c0,
};
/* Where each function starts in `kernels`, in bytes. */
enum { FIB = 0x0, INTERP = 0x40, PTRS = 0xbc, F0 = 0x104, F1 = 0x10c, F2 = 0x114,
       F3 = 0x11c, LOOP = 0x124, DRIVER = 0x148 };

/* One of the `functions` benchmark's: 16 words, the first's immediate
 * made the function's own (reads x2, writes x0, x1 and x3). */
static const unsigned body[16] = {
    0x91000000, /* add x0, x0, #k */
    0xca000021, /* eor x1, x1, x0 */
    0xeb02001f, /* cmp x0, x2 */
    0x5400004b, /* b.lt +8 */
    0xd1000400, /* sub x0, x0, #1 */
    0x8b000421, /* add x1, x1, x0, lsl #1 */
    0x93c00c23, /* extr x3, x1, x0, #3 */
    0xca030000, /* eor x0, x0, x3 */
    0xf100047f, /* cmp x3, #1 */
    0x54000040, /* b.eq +8 */
    0x91000821, /* add x1, x1, #2 */
    0x8a010003, /* and x3, x0, x1 */
    0xaa030021, /* orr x1, x1, x3 */
    0xd341fc00, /* lsr x0, x0, #1 */
    0x8b010000, /* add x0, x0, x1 */
    0xd65f03c0, /* ret */
};

/* Memory to write code into and run it from: writable and executable at
 * once (macOS: `MAP_JIT`, writable or executable for each thread in
 * turn). */
static unsigned *code_room(size_t bytes) {
#ifdef __APPLE__
    int flags = MAP_PRIVATE | MAP_ANON | MAP_JIT;
#else
    int flags = MAP_PRIVATE | MAP_ANON;
#endif
    void *p = mmap(NULL, bytes, PROT_READ | PROT_WRITE | PROT_EXEC, flags, -1, 0);
    return p == MAP_FAILED ? NULL : p;
}

static void code_writable(int on) {
#ifdef __APPLE__
    pthread_jit_write_protect_np(!on);
#else
    (void)on;
#endif
}

/* Words written at `p`, made visible to instruction fetch. */
static void code_ready(unsigned *p, size_t words) {
    code_writable(0);
    __builtin___clear_cache((char *)p, (char *)(p + words));
}

/* A random number (a linear congruential generator). */
static unsigned long lcg = 12345;
static unsigned long rnd(void) {
    lcg = lcg * 6364136223846793005ul + 1442695040888963407ul;
    return lcg >> 33;
}

/* `bench jit KIND N`: nanoseconds (microseconds for `made`) each, or -1
 * if the code computed something else. */
static double jit(const char *kind, long n) {
    unsigned *c = code_room(1 << 22);
    if (c == NULL) {
        return -1;
    }
    code_writable(1);
    memcpy(c, kernels, sizeof kernels);
    code_ready(c, sizeof kernels / 4);
    char *at = (char *)c;
    double start;
    if (strcmp(kind, "calls") == 0) {
        long (*fib)(long) = (long (*)(long))(at + FIB);
        fib(20);
        start = now_ns();
        long sum = 0;
        for (long i = 0; i < n; i++) {
            sum += fib(20);
        }
        /* fib 20 is 6765, made in 21891 calls. */
        return sum == 6765 * n ? (now_ns() - start) / n / 21891 : -1;
    }
    if (strcmp(kind, "indirect") == 0) {
        static const unsigned char prog[] = {0, 1, 2, 3, 4, 5, 6, 0, 2, 3, 1, 7};
        long (*interp)(const unsigned char *, long) =
            (long (*)(const unsigned char *, long))(at + INTERP);
        interp(prog, 1000);
        start = now_ns();
        interp(prog, n);
        return (now_ns() - start) / n / 12;
    }
    if (strcmp(kind, "pointers") == 0) {
        long (*table[4])(long);
        int offs[4] = {F0, F1, F2, F3};
        for (int i = 0; i < 4; i++) {
            table[i] = (long (*)(long))(at + offs[i]);
        }
        long (*ptrs)(long (**)(long), long) = (long (*)(long (**)(long), long))(at + PTRS);
        ptrs(table, 1000);
        start = now_ns();
        ptrs(table, n);
        return (now_ns() - start) / n;
    }
    if (strcmp(kind, "loop") == 0) {
        long (*loop)(long) = (long (*)(long))(at + LOOP);
        long v = 0;
        for (long i = 0; i < 1000; i++) {
            v = v * 31 + i;
        }
        if (loop(1000) != v) {
            return -1;
        }
        start = now_ns();
        loop(n);
        return (now_ns() - start) / n;
    }
    if (strcmp(kind, "functions") == 0) {
        enum { K = 4096 };
        unsigned *f = c + (1 << 16);
        static long (*table[K])(long);
        code_writable(1);
        for (int k = 0; k < K; k++) {
            memcpy(f + 16 * k, body, sizeof body);
            f[16 * k] |= (unsigned)(k & 0xfff) << 10;
            table[k] = (long (*)(long))(f + 16 * k);
        }
        code_ready(f, 16 * K);
        unsigned *idx = malloc(n * sizeof *idx);
        if (idx == NULL) {
            return -1;
        }
        for (long i = 0; i < n; i++) {
            idx[i] = (unsigned)(rnd() % K);
        }
        void (*driver)(unsigned *, long (**)(long), long) =
            (void (*)(unsigned *, long (**)(long), long))(at + DRIVER);
        driver(idx, table, n);
        start = now_ns();
        driver(idx, table, n);
        double ns = (now_ns() - start) / n;
        free(idx);
        return ns;
    }
    if (strcmp(kind, "made") == 0) {
        /* Each function `add x0, x0, #(k + salt)`, `ret`, 16 bytes apart,
         * `salt` this process's own: words no earlier process wrote there,
         * so their translations are made, not taken from those kept. */
        unsigned *f = c + (1 << 16);
        if (n > (1 << 16)) {
            return -1;
        }
        long salt = (long)now_ns() >> 10;
        code_writable(1);
        for (long k = 0; k < n; k++) {
            f[4 * k] = 0x91000000 | (unsigned)((k + salt) & 0xfff) << 10;
            f[4 * k + 1] = 0xd65f03c0;
        }
        code_ready(f, 4 * n);
        long v = 0;
        start = now_ns();
        for (long k = 0; k < n; k++) {
            v = ((long (*)(long))(f + 4 * k))(v);
        }
        double us = (now_ns() - start) / n / 1e3;
        long want = 0;
        for (long k = 0; k < n; k++) {
            want += (k + salt) & 0xfff;
        }
        return v == want ? us : -1;
    }
    return -1;
}

/* The X connection: its socket, a buffer for replies, the next
 * resource id. */
static int xfd = -1;
static unsigned char xbuf[1 << 16];
static unsigned xid;

static int xput(const void *p, size_t n) {
    const unsigned char *b = p;
    while (n > 0) {
        ssize_t r = write(xfd, b, n);
        if (r <= 0) return -1;
        b += r;
        n -= (size_t)r;
    }
    return 0;
}

static int xget(void *p, size_t n) {
    unsigned char *b = p;
    while (n > 0) {
        ssize_t r = read(xfd, b, n);
        if (r <= 0) return -1;
        b += r;
        n -= (size_t)r;
    }
    return 0;
}

static unsigned x16(const unsigned char *p) { return p[0] | p[1] << 8; }
static unsigned x32(const unsigned char *p) { return p[0] | p[1] << 8 | p[2] << 16 | (unsigned)p[3] << 24; }

/* The next reply into xbuf (an error is -1; events are passed over). */
static int xreply(void) {
    for (;;) {
        if (xget(xbuf, 32) < 0 || xbuf[0] == 0) return -1;
        if (xbuf[0] == 1) {
            size_t more = 4 * (size_t)x32(xbuf + 4);
            return more > sizeof xbuf - 32 || xget(xbuf + 32, more) < 0 ? -1 : 0;
        }
    }
}

/* A request: its words, the length put in. */
static int xreq(unsigned *w, unsigned words) {
    w[0] |= words << 16;
    return xput(w, 4 * words);
}

/* GetInputFocus, waited for: a round trip. */
static int xsync(void) {
    unsigned w[1] = {43};
    return xreq(w, 1) < 0 ? -1 : xreply();
}

/* Connect to DISPLAY with no authorization: the root window and depth. */
static int xconnect(unsigned *root, unsigned *depth) {
    const char *d = getenv("DISPLAY");
    if (!d || d[0] != ':') return -1;
    struct sockaddr_un a = {.sun_family = AF_UNIX};
    snprintf(a.sun_path, sizeof a.sun_path, "/tmp/.X11-unix/X%d", atoi(d + 1));
    xfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (xfd < 0 || connect(xfd, (struct sockaddr *)&a, sizeof a) != 0) return -1;
    unsigned char setup[12] = {'l', 0, 11, 0};
    if (xput(setup, 12) < 0 || xget(xbuf, 8) < 0 || xbuf[0] != 1) return -1;
    if (xget(xbuf + 8, 4 * x16(xbuf + 6)) < 0) return -1;
    xid = x32(xbuf + 12);
    unsigned vendor = x16(xbuf + 24), formats = xbuf[29];
    const unsigned char *screen = xbuf + 40 + ((vendor + 3) & ~3u) + 8 * formats;
    *root = x32(screen);
    *depth = screen[38];
    return 0;
}

static double x11(const char *what, long n) {
    unsigned root, depth;
    if (xconnect(&root, &depth) < 0) return -1;
    if (strcmp(what, "rtt") == 0) {
        double start = now_ns();
        for (long i = 0; i < n; i++)
            if (xsync() < 0) return -1;
        return (now_ns() - start) / n / 1e3;
    }
    if (strcmp(what, "shm") != 0) return -1;
    enum { W = 512, H = 512 };
    /* QueryExtension("MIT-SHM"). */
    unsigned q[4] = {98, 7};
    memcpy(q + 2, "MIT-SHM\0", 8);
    if (xreq(q, 4) < 0 || xreply() < 0 || !xbuf[8]) return -1;
    unsigned shm = xbuf[9];
    unsigned win = xid++, gc = xid++, seg = xid++;
    /* CreateWindow (copying the parent's depth and visual), mapped. */
    unsigned cw[8] = {1 | depth << 8, win, root, 0, W | H << 16, 0, 0, 0};
    unsigned map[2] = {8, win};
    unsigned cg[4] = {55, gc, win, 0};
    if (xreq(cw, 8) < 0 || xreq(map, 2) < 0 || xreq(cg, 4) < 0) return -1;
    int id = shmget(IPC_PRIVATE, W * H * 4, IPC_CREAT | 0600);
    unsigned *pixels = id < 0 ? (void *)-1 : shmat(id, 0, 0);
    if (pixels == (void *)-1) return -1;
    /* ShmAttach (read-write). */
    unsigned at[4] = {shm | 1 << 8, seg, (unsigned)id, 0};
    if (xreq(at, 4) < 0 || xsync() < 0) {
        shmctl(id, IPC_RMID, 0);
        return -1;
    }
    /* Each frame's pixels are new, but only their trip is timed: the loop
       that makes them is the compiler's (each side's build vectorizes it
       differently), not the system's. */
    double took = 0;
    for (long i = 0; i < n; i++) {
        for (unsigned k = 0; k < W * H; k++) pixels[k] = (k + (unsigned)i) * 2654435761u;
        double start = now_ns();
        /* ShmPutImage: all of it, ZPixmap, at the window's origin. */
        unsigned put[10] = {shm | 3 << 8, win, gc, W | H << 16, 0, W | H << 16, 0,
                            depth | 2 << 8, seg, 0};
        if (xreq(put, 10) < 0 || xsync() < 0) {
            shmctl(id, IPC_RMID, 0);
            return -1;
        }
        took += now_ns() - start;
    }
    double us = took / n / 1e3;
    shmctl(id, IPC_RMID, 0);
    return us;
}

/* `bench ipc OP N`: nanoseconds a round, or -1 if OP failed or is not
   offered here. */
static double ipc(const char *op, long n) {
    double start;
    if (strcmp(op, "sem") == 0) {
        int id = semget(IPC_PRIVATE, 1, IPC_CREAT | 0600);
        if (id < 0) return -1;
        struct sembuf up = {0, 1, 0}, down = {0, -1, 0};
        start = now_ns();
        for (long i = 0; i < n; i++)
            if (semop(id, &up, 1) != 0 || semop(id, &down, 1) != 0) {
                semctl(id, 0, IPC_RMID);
                return -1;
            }
        double each = (now_ns() - start) / n;
        semctl(id, 0, IPC_RMID);
        return each;
    }
    if (strcmp(op, "msg") == 0) {
        int id = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
        if (id < 0) return -1;
        struct { long type; char text[64]; } m = {1, {0}};
        start = now_ns();
        for (long i = 0; i < n; i++)
            if (msgsnd(id, &m, sizeof m.text, 0) != 0 ||
                msgrcv(id, &m, sizeof m.text, 0, 0) != (ssize_t)sizeof m.text) {
                msgctl(id, IPC_RMID, NULL);
                return -1;
            }
        double each = (now_ns() - start) / n;
        msgctl(id, IPC_RMID, NULL);
        return each;
    }
    if (strcmp(op, "shm") == 0) {
        start = now_ns();
        for (long i = 0; i < n; i++) {
            int id = shmget(IPC_PRIVATE, 65536, IPC_CREAT | 0600);
            if (id < 0) return -1;
            volatile char *p = shmat(id, NULL, 0);
            if (p == (void *)-1) return -1;
            p[0] = (char)i;
            shmdt((void *)p);
            shmctl(id, IPC_RMID, NULL);
        }
        return (now_ns() - start) / n;
    }
    if (strcmp(op, "pshm") == 0) {
        /* What a segment of its own costs the host at least: a POSIX
           shared memory object made, sized, mapped, touched, unmapped and
           removed, as fwe makes each System V segment. */
        char name[32];
        snprintf(name, sizeof name, "/fwe-bench-%d", (int)getpid());
        start = now_ns();
        for (long i = 0; i < n; i++) {
            int fd = shm_open(name, O_RDWR | O_CREAT | O_EXCL, 0600);
            if (fd < 0) return -1;
            if (ftruncate(fd, 65536) != 0) return -1;
            volatile char *p = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            close(fd);
            if (p == MAP_FAILED) return -1;
            p[0] = (char)i;
            munmap((void *)p, 65536);
            shm_unlink(name);
        }
        return (now_ns() - start) / n;
    }
#ifdef __linux__
    if (strcmp(op, "eventfd") == 0) {
        int fd = eventfd(0, 0);
        if (fd < 0) return -1;
        uint64_t v = 1;
        start = now_ns();
        for (long i = 0; i < n; i++)
            if (write(fd, &v, 8) != 8 || read(fd, &v, 8) != 8) return -1;
        double each = (now_ns() - start) / n;
        close(fd);
        return each;
    }
    if (strcmp(op, "futex") == 0) {
        int *w = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        if (w == MAP_FAILED) return -1;
        start = now_ns();
        for (long i = 0; i < n; i++)
            if (syscall(SYS_futex, w, FUTEX_WAKE, 1, NULL, NULL, 0) < 0) return -1;
        double each = (now_ns() - start) / n;
        munmap(w, 4096);
        return each;
    }
#endif
    return -1;
}

/* A fault's handler: on past the faulting load. */
static void step_past(int sig, siginfo_t *si, void *ctx) {
    (void)sig;
    (void)si;
    ucontext_t *uc = ctx;
#ifdef __APPLE__
    uc->uc_mcontext->__ss.__pc += 4;
#else
    uc->uc_mcontext.pc += 4;
#endif
    faults++;
}

int main(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[1], "exit") == 0) {
        return 0;
    }
    long n = argc > 2 ? atol(argv[2]) : 1000;
    double start = now_ns();
    if (strcmp(argv[1], "syscall") == 0) {
        volatile long sink = 0;
        for (long i = 0; i < n; i++) {
            sink += getppid();
        }
        printf("%.1f\n", (now_ns() - start) / n);
    } else if (strcmp(argv[1], "getpid") == 0) {
        for (long i = 0; i < n; i++) {
            syscall(SYS_getpid);
        }
        printf("%.1f\n", (now_ns() - start) / n);
    } else if (strcmp(argv[1], "nr") == 0) {
        long nr = n;
        n = argc > 3 ? atol(argv[3]) : 1000;
        start = now_ns();
        for (long i = 0; i < n; i++) {
            syscall(nr);
        }
        printf("%.1f\n", (now_ns() - start) / n);
    } else if (strcmp(argv[1], "fork") == 0) {
        for (long i = 0; i < n; i++) {
            pid_t pid = fork();
            if (pid == 0) {
                _exit(0);
            }
            waitpid(pid, NULL, 0);
        }
        printf("%.1f\n", (now_ns() - start) / n / 1e3);
    } else if (strcmp(argv[1], "forkexec") == 0) {
        char *const args[] = {argv[3], "exit", NULL};
        for (long i = 0; i < n; i++) {
            pid_t pid = fork();
            if (pid == 0) {
                execv(argv[3], args);
                _exit(127);
            }
            int status = 0;
            waitpid(pid, &status, 0);
            if (status != 0) {
                fprintf(stderr, "child failed: %d\n", status);
                return 1;
            }
        }
        printf("%.1f\n", (now_ns() - start) / n / 1e3);
    } else if (strcmp(argv[1], "fault") == 0) {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_sigaction = step_past;
        sa.sa_flags = SA_SIGINFO;
        sigaction(SIGSEGV, &sa, NULL);
        sigaction(SIGBUS, &sa, NULL);
        start = now_ns();
        for (long i = 0; i < n; i++) {
            /* One load, through a register holding 0. */
            __asm__ volatile("mov x10, #0\n ldr x9, [x10]" ::: "x9", "x10", "memory");
        }
        if (faults != n) {
            return 1;
        }
        printf("%.2f\n", (now_ns() - start) / n / 1e3);
    } else if (strcmp(argv[1], "thread") == 0) {
        for (long i = 0; i < n; i++) {
            pthread_t t;
            pthread_create(&t, NULL, nothing, NULL);
            pthread_join(t, NULL);
        }
        printf("%.1f\n", (now_ns() - start) / n / 1e3);
    } else if (strcmp(argv[1], "par") == 0) {
        par_op = argv[2];
        long threads = argc > 3 ? atol(argv[3]) : 1;
        par_calls = argc > 4 ? atol(argv[4]) : 1000;
        pthread_t t[64];
        if (threads < 1 || threads > 64) {
            return 2;
        }
        start = now_ns();
        for (long i = 0; i < threads; i++) {
            pthread_create(&t[i], NULL, par, NULL);
        }
        for (long i = 0; i < threads; i++) {
            pthread_join(t[i], NULL);
        }
        printf("%.1f\n", (now_ns() - start) / par_calls);
    } else if (strcmp(argv[1], "jit") == 0) {
        double each = jit(argv[2], argc > 3 ? atol(argv[3]) : 1000);
        if (each < 0) {
            return 1;
        }
        printf("%.2f\n", each);
    } else if (strcmp(argv[1], "file") == 0) {
        const char *op = argv[2];
        n = argc > 3 ? atol(argv[3]) : 1000;
        char path[] = "/tmp/fwe-bench-XXXXXX";
        int fd = mkstemp(path);
        static char buf[65536];
        if (fd < 0 || write(fd, buf, sizeof buf) != (long)sizeof buf) {
            return 1;
        }
        struct stat st;
        volatile long sink = 0;
        start = now_ns();
        for (long i = 0; i < n; i++) {
            if (strcmp(op, "pread") == 0) {
                sink += pread(fd, buf, 4096, 0);
            } else if (strcmp(op, "stat") == 0) {
                sink += stat(path, &st);
            } else if (strcmp(op, "open") == 0) {
                int f = open(path, O_RDONLY);
                sink += close(f);
            } else if (strcmp(op, "proc") == 0) {
                /* A synthetic file: opened, read whole, closed. */
                int f = open("/proc/self/stat", O_RDONLY);
                sink += read(f, buf, 4096);
                sink += close(f);
            } else if (strcmp(op, "mmap") == 0) {
                void *m = mmap(NULL, 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
                sink += munmap(m, 65536);
            } else {
                return 2;
            }
        }
        printf("%.1f\n", (now_ns() - start) / n);
        close(fd);
        unlink(path);
    } else if (strcmp(argv[1], "ipc") == 0) {
        double each = ipc(argv[2], argc > 3 ? atol(argv[3]) : 1000);
        if (each < 0) {
            fprintf(stderr, "ipc %s: failed, or not offered here\n", argv[2]);
            return 1;
        }
        printf("%.1f\n", each);
    } else if (strcmp(argv[1], "x11") == 0) {
        double each = x11(argv[2], argc > 3 ? atol(argv[3]) : 1000);
        if (each < 0) {
            fprintf(stderr, "x11 %s: no X display, or it refused\n", argv[2]);
            return 1;
        }
        printf("%.2f\n", each);
    } else {
        fprintf(stderr, "unknown benchmark %s\n", argv[1]);
        return 2;
    }
    return 0;
}
