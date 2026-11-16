/* cgroups made, joined, left and removed by processes side by side, as
 * LTP's tests that use cgroups do under one shared parent: each makes a
 * cgroup of its own under the parent (made by whichever comes first, and
 * removed by whichever finds it empty), moves into it and out, and removes
 * it. None of that fails for another's removal of the parent: a removal
 * that finds a child is EBUSY, whatever comes between.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

typedef long ssize_t;
typedef unsigned long size_t;

int open(const char *path, int flags, ...);
ssize_t read(int fd, void *buf, size_t n);
ssize_t write(int fd, const void *buf, size_t n);
int close(int fd);
int mkdir(const char *path, unsigned mode);
int rmdir(const char *path);
int fork(void);
int getpid(void);
int waitpid(int pid, int *status, int options);
int pipe(int fds[2]);
void _exit(int status);
int snprintf(char *s, size_t n, const char *format, ...);
int printf(const char *format, ...);
size_t strlen(const char *s);
int *__errno_location(void);

#define EEXIST 17
#define ENOENT 2
#define EBUSY 16
#define WORKERS 12
#define ROUNDS 150

static int put(const char *path, const char *text) {
    int fd = open(path, 1);
    if (fd < 0)
        return -1;
    int r = write(fd, text, strlen(text)) == (ssize_t)strlen(text) ? 0 : -1;
    close(fd);
    return r;
}

/* One worker's rounds: the steps that failed. */
static int worker(const char *parent) {
    char mine[96], procs[128], pid[16];
    snprintf(mine, sizeof mine, "%s/w-%d", parent, getpid());
    snprintf(procs, sizeof procs, "%s/cgroup.procs", mine);
    snprintf(pid, sizeof pid, "%d", getpid());
    int failed = 0;
    for (int round = 0; round < ROUNDS; round++) {
        /* (The parent may go between, removed by another: made again.) */
        int made;
        do {
            if (mkdir(parent, 0755) != 0 && *__errno_location() != EEXIST)
                failed++;
            made = mkdir(mine, 0755) == 0;
        } while (!made && *__errno_location() == ENOENT);
        if (!made) {
            failed++;
            continue;
        }
        if (put(procs, pid) != 0)
            failed++;
        if (put("/sys/fs/cgroup/cgroup.procs", pid) != 0)
            failed++;
        if (rmdir(mine) != 0)
            failed++;
        /* The last one out takes the parent. */
        if (rmdir(parent) != 0 && *__errno_location() != EBUSY && *__errno_location() != ENOENT)
            failed++;
    }
    return failed;
}

int main(void) {
    char parent[64];
    snprintf(parent, sizeof parent, "/sys/fs/cgroup/race-%d", getpid());
    int fds[2];
    if (pipe(fds) != 0)
        return 2;
    int pids[WORKERS];
    for (int w = 0; w < WORKERS; w++) {
        pids[w] = fork();
        if (pids[w] < 0)
            return 2;
        if (pids[w] == 0) {
            int failed = worker(parent);
            write(fds[1], &failed, sizeof failed);
            _exit(0);
        }
    }
    int total = 0;
    for (int w = 0; w < WORKERS; w++) {
        int failed = 0;
        if (read(fds[0], &failed, sizeof failed) != sizeof failed)
            failed = 1;
        total += failed;
        waitpid(pids[w], 0, 0);
    }
    rmdir(parent);
    printf("failed steps: %d\n", total);
    return 0;
}
