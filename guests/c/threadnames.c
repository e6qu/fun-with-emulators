/* Thread names (comm), as Linux keeps them: each thread has its own, set
 * by PR_SET_NAME or by a write to /proc/self/task/<tid>/comm (any thread
 * of the process's, as pthread_setname_np does for another); a thread
 * starts with its creator's, a fork child with the forking thread's, and
 * execve names the thread after the program's file. Another process reads
 * each in /proc/<pid>/task/<tid>/{comm,stat,status}. */
typedef unsigned long pthread_t;
int printf(const char *fmt, ...);
int snprintf(char *buf, unsigned long n, const char *fmt, ...);
int pthread_create(pthread_t *t, const void *attr, void *(*fn)(void *), void *arg);
int pthread_join(pthread_t t, void **ret);
int pthread_setname_np(pthread_t t, const char *name);
int pthread_getname_np(pthread_t t, char *name, unsigned long len);
int prctl(int option, ...);
int fork(void);
int getpid(void);
int waitpid(int pid, int *status, int options);
int execv(const char *path, char *const argv[]);
int pipe(int fds[2]);
long read(int fd, void *buf, unsigned long n);
long write(int fd, const void *buf, unsigned long n);
int open(const char *path, int flags, ...);
int close(int fd);
long syscall(long n, ...);
char *strchr(const char *s, int c);
char *strstr(const char *s, const char *t);
void _exit(int status);
int fflush(void *stream);

#define PR_SET_NAME 15
#define PR_GET_NAME 16
#define SYS_gettid 178

static int go[2], ready[2];
static int tid_self, tid_inherits, tid_named;
static pthread_t named;

/* Wait until the main thread lets the threads end. */
static void hold(void) {
    char c;
    read(go[0], &c, 1);
}

static void *inherits(void *arg) {
    (void)arg;
    __atomic_store_n(&tid_inherits, (int)syscall(SYS_gettid), __ATOMIC_RELEASE);
    write(ready[1], "i", 1);
    hold();
    return 0;
}

/* The line `path` begins with, its newline dropped. */
static const char *first_line(const char *path) {
    static char buf[512];
    int fd = open(path, 0);
    if (fd < 0) return "(none)";
    long n = read(fd, buf, sizeof buf - 1);
    close(fd);
    buf[n > 0 ? n : 0] = 0;
    char *nl = strchr(buf, '\n');
    if (nl) *nl = 0;
    return buf;
}

/* The Name line of `path` (a status file). */
static const char *status_name(const char *path) {
    static char buf[4096];
    int fd = open(path, 0);
    if (fd < 0) return "(none)";
    long n = read(fd, buf, sizeof buf - 1);
    close(fd);
    buf[n > 0 ? n : 0] = 0;
    char *name = strstr(buf, "Name:\t");
    if (!name) return "(no Name)";
    char *nl = strchr(name, '\n');
    if (nl) *nl = 0;
    return name + 6;
}

/* What another process (a fork child) reads of its parent's thread `tid`. */
static void others_view(int parent, const char *what, int tid) {
    char path[96];
    snprintf(path, sizeof path, "/proc/%d/task/%d/comm", parent, tid);
    printf("%s comm: %s\n", what, first_line(path));
    snprintf(path, sizeof path, "/proc/%d/task/%d/stat", parent, tid);
    const char *stat = first_line(path);
    const char *open_paren = strchr(stat, '(');
    const char *close_paren = open_paren ? strchr(open_paren, ')') : 0;
    printf("%s stat: %.*s\n", what, close_paren ? (int)(close_paren - open_paren + 1) : 6,
           open_paren ? open_paren : "(none)");
    snprintf(path, sizeof path, "/proc/%d/task/%d/status", parent, tid);
    printf("%s status: %s\n", what, status_name(path));
}

static void *self_named(void *arg) {
    int parent = (int)(long)arg;
    tid_self = syscall(SYS_gettid);
    prctl(PR_SET_NAME, "self-named");
    pthread_t t;
    pthread_create(&t, 0, inherits, 0);
    char c;
    read(ready[0], &c, 1); /* the inheriting thread has started */
    read(ready[0], &c, 1); /* the main thread named the other */
    /* A fork child of this thread: its name, then its parent's threads. */
    fflush(0);
    int pid = fork();
    if (pid == 0) {
        char name[16] = {0};
        prctl(PR_GET_NAME, name);
        printf("fork child: %s\n", name);
        others_view(parent, "main", parent);
        others_view(parent, "self-named", tid_self);
        others_view(parent, "inheriting", tid_inherits);
        others_view(parent, "named by main", tid_named);
        char *argv[] = {"threadnames", "exec", 0};
        fflush(0);
        execv("/proc/self/exe", argv);
        _exit(3);
    }
    int status;
    waitpid(pid, &status, 0);
    printf("child: %d\n", status);
    write(go[1], "xx", 2);
    pthread_join(t, 0);
    return 0;
}

static void *named_by_main(void *arg) {
    (void)arg;
    tid_named = syscall(SYS_gettid);
    write(ready[1], "n", 1);
    hold();
    return 0;
}

int main(int argc, char **argv) {
    (void)argv;
    if (argc > 1) {
        char name[16] = {0};
        prctl(PR_GET_NAME, name);
        printf("after execve: %s\n", name);
        return 0;
    }
    if (pipe(go) || pipe(ready)) return 1;
    pthread_create(&named, 0, named_by_main, 0);
    char c;
    read(ready[0], &c, 1);
    pthread_setname_np(named, "named-by-main");
    pthread_t s;
    pthread_create(&s, 0, self_named, (void *)(long)getpid());
    /* Wait for the inheriting thread to start. */
    while (!__atomic_load_n(&tid_inherits, __ATOMIC_ACQUIRE)) syscall(124 /* sched_yield */);
    char got[16] = {0};
    pthread_getname_np(named, got, sizeof got);
    printf("own view of the named thread: %s\n", got);
    char path[64];
    snprintf(path, sizeof path, "/proc/self/task/%d/comm", tid_inherits);
    printf("own view of the inheriting thread: %s\n", first_line(path));
    write(ready[1], "n", 1);
    pthread_join(s, 0);
    pthread_join(named, 0);
    return 0;
}
