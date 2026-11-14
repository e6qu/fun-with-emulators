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
 *   bench exit           returns at once (for startup time)
 */
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

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
    } else {
        fprintf(stderr, "unknown benchmark %s\n", argv[1]);
        return 2;
    }
    return 0;
}
