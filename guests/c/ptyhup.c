/* A pty master after its slave's last holder went: Linux keeps what the
 * slave wrote, `poll` reports it and the hang-up (POLLIN | POLLHUP, then
 * POLLHUP alone once it is read), and `read` hands it out, then fails with
 * EIO (5), never returns 0. The program that looks is a new one: the
 * master is passed on through an execve, and what the slave wrote with
 * it. A duplicate of the master is hung up too. Before any slave is
 * opened, the master is not hung up. Every line printed is what Linux
 * prints. */
int printf(const char *fmt, ...);
int fflush(void *stream);
int posix_openpt(int flags);
int grantpt(int fd);
int unlockpt(int fd);
char *ptsname(int fd);
int fork(void);
int dup(int fd);
int open(const char *path, int flags, ...);
long write(int fd, const void *buf, unsigned long n);
long read(int fd, void *buf, unsigned long n);
int waitpid(int pid, int *status, int options);
int execve(const char *path, char *const argv[], char *const envp[]);
void _exit(int status);
int *__errno_location(void);

struct pollfd {
    int fd;
    short events, revents;
};
int poll(struct pollfd *fds, unsigned long n, int timeout);

#define O_RDWR 02
#define O_NOCTTY 0400
#define POLLIN 1

/* What `poll` reports for reading master `m`: its return and revents. */
static void look(const char *when, int m, int timeout) {
    struct pollfd p = {m, POLLIN, 0};
    int n = poll(&p, 1, timeout);
    printf("%s: poll %d revents %#x\n", when, n, p.revents);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        int m = argv[1][0] - '0';
        look("after hang-up", m, 5000);
        char buf[64];
        long n = read(m, buf, sizeof buf);
        printf("first read: %ld\n", n);
        look("all read", m, 5000);
        n = read(m, buf, sizeof buf);
        printf("next read: %ld errno %d\n", n, n < 0 ? *__errno_location() : 0);
        n = read(dup(m), buf, sizeof buf);
        printf("a duplicate's read: %ld errno %d\n", n, n < 0 ? *__errno_location() : 0);
        return 0;
    }
    int m = posix_openpt(O_RDWR | O_NOCTTY);
    if (m < 0 || m > 9 || grantpt(m) != 0 || unlockpt(m) != 0) {
        printf("posix_openpt failed\n");
        return 1;
    }
    look("no slave yet", m, 0);
    char *name = ptsname(m);
    int c = fork();
    if (c == 0) {
        int s = open(name, O_RDWR | O_NOCTTY);
        if (s < 0) {
            _exit(2);
        }
        write(s, "hello\n", 6);
        _exit(0);
    }
    int status;
    waitpid(c, &status, 0);
    printf("child: %d\n", (status >> 8) & 0xff);
    char fd[2] = {(char)('0' + m), 0};
    char *next[] = {argv[0], fd, 0};
    fflush(0);
    execve("/proc/self/exe", next, 0);
    printf("execve failed\n");
    return 1;
}
