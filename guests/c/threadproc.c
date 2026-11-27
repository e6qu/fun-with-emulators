/* /proc/<tid> for a thread that is not its process's leader: Linux does
 * not list it in /proc, but opens it, its stat naming the thread, from
 * the process itself and from another (crashpad reads its threads so). */
typedef unsigned long pthread_t;
int pthread_create(pthread_t *t, const void *attr, void *(*f)(void *), void *arg);
int open(const char *path, int flags, ...);
long read(int fd, void *buf, unsigned long n);
int close(int fd);
int printf(const char *fmt, ...);
int fflush(void *f);
int snprintf(char *s, unsigned long n, const char *fmt, ...);
int usleep(unsigned us);
int fork(void);
int waitpid(int pid, int *status, int options);
void _exit(int status);
long syscall(long n, ...);
int getpid(void);
char *strchr(const char *s, int c);
int atoi(const char *s);
void *opendir(const char *path);
void *readdir(void *d);
int closedir(void *d);
int strcmp(const char *a, const char *b);

static volatile int tid;

static void *worker(void *arg) {
    (void)arg;
    tid = (int)syscall(178 /* gettid */);
    for (;;) usleep(100000);
    return 0;
}

/* The fields after the name: the state and the parent's pid. */
static void stat_of(const char *who, int id) {
    char path[64], b[512] = {0};
    snprintf(path, sizeof path, "/proc/%d/stat", id);
    int fd = open(path, 0);
    if (fd < 0) {
        printf("%s: /proc/<tid>/stat: cannot open\n", who);
        return;
    }
    long n = read(fd, b, sizeof b - 1);
    close(fd);
    int first = atoi(b);
    char *paren = strchr(b, ')');
    printf("%s: /proc/<tid>/stat: %s, names %s\n", who, n > 0 ? "read" : "empty",
           first == id ? "the thread" : "another");
    (void)paren;
}

static int listed(int id) {
    char name[16];
    snprintf(name, sizeof name, "%d", id);
    void *d = opendir("/proc");
    struct { unsigned long ino; long off; unsigned short reclen; unsigned char type; char name[256]; } *e;
    int found = 0;
    while ((e = readdir(d)))
        if (!strcmp(e->name, name)) found = 1;
    closedir(d);
    return found;
}

int main(void) {
    pthread_t t;
    pthread_create(&t, 0, worker, 0);
    while (!tid) usleep(1000);
    printf("the thread is %s in /proc\n", listed(tid) ? "listed" : "not listed");
    stat_of("the process", tid);
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/task/%d/stat", getpid(), tid);
    int fd = open(path, 0);
    printf("the process: /proc/<pid>/task/<tid>/stat: %s\n", fd >= 0 ? "opened" : "cannot open");
    if (fd >= 0) close(fd);
    fflush(0);
    int pid = fork();
    if (pid == 0) {
        stat_of("a child", tid);
        fflush(0);
        _exit(0);
    }
    waitpid(pid, 0, 0);
    return 0;
}
