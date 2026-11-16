/* A forked child is in its parent's cgroup, whichever of the two writes
 * the child's record first: each of many children finds itself among the
 * cgroup's members and its /proc/self/cgroup at the namespace's root.
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
int unshare(int flags);
int fork(void);
int getpid(void);
int waitpid(int pid, int *status, int options);
int snprintf(char *s, size_t n, const char *format, ...);
int printf(const char *format, ...);
char *strstr(const char *haystack, const char *needle);
int strcmp(const char *a, const char *b);
void _exit(int status);

#define CLONE_NEWCGROUP 0x02000000

static int slurp(const char *path, char *buf, int room) {
    int fd = open(path, 0);
    if (fd < 0) {
        return -1;
    }
    int n = (int)read(fd, buf, room - 1);
    close(fd);
    buf[n > 0 ? n : 0] = 0;
    return n;
}

int main(void) {
    char dir[64], procs[96], buf[4096];
    snprintf(dir, sizeof dir, "/sys/fs/cgroup/fork-%d", getpid());
    snprintf(procs, sizeof procs, "%s/cgroup.procs", dir);
    mkdir(dir, 0755);
    int fd = open(procs, 1);
    write(fd, "0", 1);
    close(fd);
    unshare(CLONE_NEWCGROUP);
    int wrong = 0;
    for (int i = 0; i < 50; i++) {
        int pid = fork();
        if (pid == 0) {
            char me[32];
            snprintf(me, sizeof me, "\n%d\n", getpid());
            buf[0] = '\n';
            slurp(procs, buf + 1, sizeof buf - 1);
            int listed = strstr(buf, me) != 0;
            slurp("/proc/self/cgroup", buf, sizeof buf);
            _exit(listed && strcmp(buf, "0::/\n") == 0 ? 0 : 1);
        }
        int status = 0;
        waitpid(pid, &status, 0);
        wrong += status != 0;
    }
    printf("children elsewhere: %d\n", wrong);
    return 0;
}
