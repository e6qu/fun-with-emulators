/* Two processes of a user other than root make the same names at once,
 * as PostgreSQL's parallel workers make their temporary directories: each
 * round both make directory d<r> (mode 0700; one makes it, the other finds
 * it made) and then a directory of their own in it, both open file f<r>
 * with O_CREAT (mode 0600; one makes it, the other opens it), and both
 * make FIFO p<r> (one makes it, the other finds it made). On Linux a name
 * is never seen before its owner is set, so neither is refused (EACCES)
 * in what the other made. Prints how many calls failed otherwise, and
 * "listed clean" when no name but the ones made is listed.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

typedef unsigned long size_t;
typedef long ssize_t;

int mkdir(const char *path, int mode);
int mkfifo(const char *path, int mode);
int open(const char *path, int flags, ...);
int close(int fd);
int chown(const char *path, int uid, int gid);
int chdir(const char *path);
int setgid(int gid);
int setuid(int uid);
int fork(void);
int waitpid(int pid, int *status, int options);
int pipe(int fds[2]);
ssize_t read(int fd, void *buf, size_t n);
ssize_t write(int fd, const void *buf, size_t n);
int snprintf(char *s, size_t n, const char *format, ...);
int dprintf(int fd, const char *format, ...);
int printf(const char *format, ...);
int *__errno_location(void);
void *opendir(const char *path);
void *readdir(void *dir);
int closedir(void *dir);
int strcmp(const char *a, const char *b);
void _exit(int status);

#define O_RDWR 02
#define O_CREAT 0100
#define EEXIST 17
#define ROUNDS 300
#define USER 70

/* A round's calls by process `who`: how many failed. */
static int round_of(int r, int who) {
    char d[32], sub[48], f[32], p[32];
    int failed = 0;
    snprintf(d, sizeof d, "d%d", r);
    snprintf(sub, sizeof sub, "d%d/%d", r, who);
    snprintf(f, sizeof f, "f%d", r);
    snprintf(p, sizeof p, "p%d", r);
    if (mkdir(d, 0700) != 0 && *__errno_location() != EEXIST) {
        dprintf(2, "%d: mkdir %s: errno %d\n", who, d, *__errno_location());
        failed++;
    }
    if (mkdir(sub, 0700) != 0) {
        dprintf(2, "%d: mkdir %s: errno %d\n", who, sub, *__errno_location());
        failed++;
    }
    int fd = open(f, O_RDWR | O_CREAT, 0600);
    if (fd < 0) {
        dprintf(2, "%d: open %s: errno %d\n", who, f, *__errno_location());
        failed++;
    } else {
        close(fd);
    }
    if (mkfifo(p, 0600) != 0 && *__errno_location() != EEXIST) {
        dprintf(2, "%d: mkfifo %s: errno %d\n", who, p, *__errno_location());
        failed++;
    }
    return failed;
}

/* Whether the directory lists only what the rounds made. */
static int listed_clean(void) {
    void *dir = opendir(".");
    if (!dir)
        return 0;
    int clean = 1;
    char *e;
    while ((e = readdir(dir)) != 0) {
        /* d_name, after d_ino, d_off, d_reclen and d_type. */
        char *name = e + 19;
        if (name[0] == '.' && (name[1] == 0 || (name[1] == '.' && name[2] == 0)))
            continue;
        if (name[0] != 'd' && name[0] != 'f' && name[0] != 'p') {
            dprintf(2, "listed: %s\n", name);
            clean = 0;
        }
    }
    closedir(dir);
    return clean;
}

int main(void) {
    mkdir("/tmp", 01777);
    mkdir("/tmp/makerace", 0755);
    if (chown("/tmp/makerace", USER, USER) != 0 || chdir("/tmp/makerace") != 0)
        return 2;
    if (setgid(USER) != 0 || setuid(USER) != 0)
        return 2;
    /* Each round starts in both at once: each tells the other it is
     * ready and waits for the other's word. */
    int to_child[2], to_parent[2], counts[2];
    if (pipe(to_child) != 0 || pipe(to_parent) != 0 || pipe(counts) != 0)
        return 2;
    int child = fork();
    if (child < 0)
        return 2;
    int who = child == 0;
    int failed = 0;
    char b = 0;
    for (int r = 0; r < ROUNDS; r++) {
        if (who) {
            write(to_parent[1], &b, 1);
            read(to_child[0], &b, 1);
        } else {
            write(to_child[1], &b, 1);
            read(to_parent[0], &b, 1);
        }
        failed += round_of(r, who);
    }
    if (who) {
        write(counts[1], &failed, sizeof failed);
        _exit(0);
    }
    int theirs = 0;
    if (read(counts[0], &theirs, sizeof theirs) != sizeof theirs)
        return 2;
    waitpid(child, 0, 0);
    printf("failed: %d, %s\n", failed + theirs, listed_clean() ? "listed clean" : "listed more");
    return 0;
}
