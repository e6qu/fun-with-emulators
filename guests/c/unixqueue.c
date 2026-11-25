/* Connecting to a Unix stream socket whose listener's queue is full, as
 * Linux answers: a non-blocking connect fails with EAGAIN; a blocking one
 * waits until the listener accepts, or until its send timeout (EAGAIN);
 * a socket file nothing listens on refuses (ECONNREFUSED). */
#include <stdint.h>

int printf(const char *fmt, ...);
int socket(int domain, int type, int protocol);
int bind(int fd, const void *addr, unsigned len);
int listen(int fd, int backlog);
int accept(int fd, void *addr, void *len);
int connect(int fd, const void *addr, unsigned len);
int setsockopt(int fd, int level, int name, const void *val, unsigned len);
int close(int fd);
int unlink(const char *path);
int *__errno_location(void);
int pthread_create(unsigned long *t, const void *attr, void *(*f)(void *), void *arg);
int pthread_join(unsigned long t, void **ret);
int usleep(unsigned us);
struct timespec {
    long tv_sec, tv_nsec;
};
int clock_gettime(int clock, struct timespec *t);

#define AF_UNIX 1
#define SOCK_STREAM 1
#define SOCK_NONBLOCK 04000
#define SOL_SOCKET 1
#define SO_SNDTIMEO 21
#define EAGAIN 11
#define ECONNREFUSED 111

static struct {
    uint16_t family;
    char path[108];
} addr = {AF_UNIX, "/unixqueue.sock"};

static long ms(void) {
    struct timespec t;
    clock_gettime(1, &t);
    return t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static const char *name(int e) {
    return e == EAGAIN ? "EAGAIN" : e == ECONNREFUSED ? "ECONNREFUSED" : "another error";
}

static int listener;
static void *accept_later(void *arg) {
    (void)arg;
    usleep(300000);
    accept(listener, 0, 0);
    return 0;
}

int main(void) {
    unlink(addr.path);
    listener = socket(AF_UNIX, SOCK_STREAM, 0);
    if (bind(listener, &addr, sizeof addr) != 0) {
        printf("bind: errno %d\n", *__errno_location());
        return 1;
    }
    if (listen(listener, 1) != 0) {
        printf("listen: errno %d\n", *__errno_location());
        return 1;
    }
    /* Fill its queue: non-blocking connects until one is turned away. */
    int queued = 0, e = 0;
    for (; queued < 64; queued++) {
        int c = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (connect(c, &addr, sizeof addr) != 0) {
            e = *__errno_location();
            close(c);
            break;
        }
    }
    printf("a full queue, not blocking: %s\n", name(e));

    /* Blocking, with a send timeout and nobody accepting: EAGAIN after it. */
    int c = socket(AF_UNIX, SOCK_STREAM, 0);
    struct { long sec, usec; } timeout = {0, 200000};
    setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
    long began = ms();
    int r = connect(c, &addr, sizeof addr);
    e = *__errno_location();
    long took = ms() - began;
    printf("a full queue, with a timeout: %s, %s\n", r == 0 ? "connected" : name(e),
           took >= 150 ? "after it" : "at once");
    close(c);

    /* Blocking: waits until the listener accepts one. */
    unsigned long t;
    pthread_create(&t, 0, accept_later, 0);
    c = socket(AF_UNIX, SOCK_STREAM, 0);
    began = ms();
    r = connect(c, &addr, sizeof addr);
    e = *__errno_location();
    took = ms() - began;
    pthread_join(t, 0);
    printf("a full queue, blocking: %s, %s\n", r == 0 ? "connected" : name(e),
           took >= 200 ? "once one was accepted" : "at once");

    /* Its file with no listener behind it: refused. */
    close(listener);
    c = socket(AF_UNIX, SOCK_STREAM, 0);
    r = connect(c, &addr, sizeof addr);
    printf("no listener: %s\n", r == 0 ? "connected" : name(*__errno_location()));
    unlink(addr.path);
    return 0;
}
