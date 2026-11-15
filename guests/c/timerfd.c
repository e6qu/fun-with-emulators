/* timerfd schedules as Linux's: an absolute time is on the timer's own
 * clock (CLOCK_MONOTONIC, CLOCK_BOOTTIME, CLOCK_REALTIME), and a periodic
 * timer first expires at its it_value, then every it_interval.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

struct timespec {
    long tv_sec;
    long tv_nsec;
};
struct itimerspec {
    struct timespec it_interval;
    struct timespec it_value;
};

int timerfd_create(int clockid, int flags);
int timerfd_settime(int fd, int flags, const struct itimerspec *new_value,
                    struct itimerspec *old_value);
int timerfd_gettime(int fd, struct itimerspec *curr_value);
int clock_gettime(int clockid, struct timespec *tp);
long read(int fd, void *buf, unsigned long count);
int close(int fd);
int printf(const char *format, ...);

#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1
#define CLOCK_BOOTTIME 7
#define TFD_TIMER_ABSTIME 1

static long now_ns(int clock) {
    struct timespec t;
    clock_gettime(clock, &t);
    return t.tv_sec * 1000000000L + t.tv_nsec;
}

/* An absolute time 50 ms ahead on `clock`: a blocking read returns one
 * expiry no sooner. */
static int absolute(int clock) {
    int fd = timerfd_create(clock, 0);
    long at = now_ns(clock) + 50000000L;
    struct itimerspec spec = {{0, 0}, {at / 1000000000L, at % 1000000000L}};
    long start = now_ns(CLOCK_MONOTONIC);
    if (timerfd_settime(fd, TFD_TIMER_ABSTIME, &spec, 0) != 0)
        return printf("clock %d: settime failed\n", clock), 1;
    unsigned long long n = 0;
    if (read(fd, &n, 8) != 8)
        return printf("clock %d: read failed\n", clock), 1;
    long took = now_ns(CLOCK_MONOTONIC) - start;
    close(fd);
    if (n != 1 || took < 45000000L || took > 2000000000L)
        return printf("clock %d: %llu expiries after %ld ns\n", clock, n, took), 1;
    printf("clock %d: absolute time kept\n", clock);
    return 0;
}

int main(void) {
    int bad = absolute(CLOCK_MONOTONIC) | absolute(CLOCK_BOOTTIME) | absolute(CLOCK_REALTIME);

    /* First after 20 ms, then every 300 ms: the first read comes at the
     * value, and the time left then is about an interval. */
    int fd = timerfd_create(CLOCK_MONOTONIC, 0);
    struct itimerspec spec = {{0, 300000000L}, {0, 20000000L}};
    long start = now_ns(CLOCK_MONOTONIC);
    timerfd_settime(fd, 0, &spec, 0);
    unsigned long long n = 0;
    read(fd, &n, 8);
    long took = now_ns(CLOCK_MONOTONIC) - start;
    struct itimerspec cur;
    timerfd_gettime(fd, &cur);
    close(fd);
    if (n != 1 || took > 250000000L || cur.it_value.tv_nsec < 150000000L)
        return printf("periodic: %llu after %ld ns, %ld left\n", n, took, cur.it_value.tv_nsec), 1;
    printf("periodic: first at its value\n");
    return bad;
}
