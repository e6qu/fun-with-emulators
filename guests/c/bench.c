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
 *   bench exit           returns at once (for startup time)
 */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
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
    } else {
        fprintf(stderr, "unknown benchmark %s\n", argv[1]);
        return 2;
    }
    return 0;
}
