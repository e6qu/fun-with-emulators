/* /proc as programs read it: the host's memory in meminfo and sysinfo,
 * cpuinfo in Linux's arm64 format, the process's environ, limits, statm
 * and io, comm and the host name written, another process's cwd, environ,
 * limits and mounts (and EACCES for those only a tracer can read to one
 * that cannot trace it), /proc/net, and a directory's link count (the
 * task directory's 2 and its threads, which sandboxes read to tell a
 * process is single-threaded). Runs as root with FWE_PROC=1 in its
 * environment.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

#include "kapi.h"

int sysinfo(void *info);
long sysconf(int name);
ssize_t readlink(const char *path, char *buf, size_t size);
int uname(void *buf);

#define PR_GET_NAME 16
#define _SC_NPROCESSORS_ONLN 84
#define AF_INET 2
#define AF_UNIX 1
#define SOCK_STREAM 1
#define SIOCGIFFLAGS 0x8913
#define SIOCSIFFLAGS 0x8914
#define IFF_UP 1

struct ksysinfo {
    long uptime;
    unsigned long loads[3];
    unsigned long totalram, freeram, sharedram, bufferram, totalswap, freeswap;
    unsigned short procs, pad;
    unsigned long totalhigh, freehigh;
    unsigned mem_unit;
    char rest[8];
};

struct sockaddr_in {
    unsigned short family, port;
    unsigned addr;
    char zero[8];
};

struct sockaddr_un {
    unsigned short family;
    char path[108];
};

struct ifreq {
    char name[16];
    short flags;
    char rest[22];
};

static char buf[65536], path[256];

static long field(const char *text, const char *name) {
    char *at = strstr(text, name);
    return at ? strtol(at + strlen(name), 0, 10) : -1;
}

static int has_var(const char *env, long n, const char *var) {
    for (long i = 0; i < n; i += strlen(env + i) + 1) {
        if (strcmp(env + i, var) == 0) {
            return 1;
        }
    }
    return 0;
}

static void memory(void) {
    struct ksysinfo si;
    sysinfo(&si);
    slurp("/proc/meminfo", buf, sizeof buf);
    long total = field(buf, "MemTotal:");
    printf("meminfo is sysinfo's: %d, procs counted: %d\n",
           total > 0 && (unsigned long)total == si.totalram / 1024, si.procs >= 1);
    slurp("/proc/cpuinfo", buf, sizeof buf);
    int cpus = 0;
    for (char *c = buf; (c = strstr(c, "processor\t: ")); c++) {
        cpus++;
    }
    printf("cpuinfo: cpus %d, BogoMIPS %d, Features fp asimd %d, BHID %d\n",
           cpus == sysconf(_SC_NPROCESSORS_ONLN), strstr(buf, "BogoMIPS\t: ") != 0,
           strstr(buf, "Features\t: fp asimd") != 0, strstr(buf, "BHID") != 0);
}

static void own(void) {
    long n = slurp("/proc/self/environ", buf, sizeof buf);
    printf("environ has FWE_PROC=1: %d\n", has_var(buf, n, "FWE_PROC=1"));
    slurp("/proc/self/limits", buf, sizeof buf);
    printf("limits: %.25s| open files %d\n", buf, strstr(buf, "\nMax open files ") != 0);
    slurp("/proc/self/statm", buf, sizeof buf);
    int words = 0;
    for (char *c = buf; *c; c++) {
        words += *c == ' ' || *c == '\n';
    }
    printf("statm words: %d\n", words);
    /* An open /proc file is named by its process's own directory. */
    int f = open("/proc/self/statm", O_RDONLY);
    char link[64], want[64];
    snprintf(link, sizeof link, "/proc/self/fd/%d", f);
    long l = readlink(link, buf, sizeof buf - 1);
    buf[l < 0 ? 0 : l] = 0;
    snprintf(want, sizeof want, "/proc/%d/statm", getpid());
    printf("open statm's link is its pid's: %d\n", strcmp(buf, want) == 0);
    close(f);
    slurp("/proc/self/io", buf, sizeof buf);
    printf("io read_bytes: %d\n", strstr(buf, "\nread_bytes: ") != 0);
    printf("comm write: %d\n", put("/proc/self/comm", "renamed"));
    char name[16] = {0};
    prctl(PR_GET_NAME, name);
    slurp("/proc/self/comm", buf, sizeof buf);
    printf("comm now: %sname: %s\n", buf, name);
}

static void hostname(void) {
    printf("hostname in the initial namespace: %d\n", -put("/proc/sys/kernel/hostname", "x"));
    fflush(0);
    pid_t pid = fork();
    if (pid == 0) {
        unshare(CLONE_NEWUTS);
        printf("hostname in a new one: %d\n", put("/proc/sys/kernel/hostname", "inner\nrest"));
        char uts[6][65];
        uname(uts);
        printf("uname nodename: %s\n", uts[1]);
        fflush(0);
        _exit(0);
    }
    reap(pid);
}

static void other(void) {
    int ready[2], done[2];
    pipe(ready);
    pipe(done);
    fflush(0);
    pid_t pid = fork();
    if (pid == 0) {
        chdir("/tmp");
        write(ready[1], "x", 1);
        char c;
        read(done[0], &c, 1);
        _exit(0);
    }
    char c;
    read(ready[0], &c, 1);
    snprintf(path, sizeof path, "/proc/%d/cwd", pid);
    long n = readlink(path, buf, sizeof buf - 1);
    buf[n < 0 ? 0 : n] = 0;
    printf("child's cwd: %s\n", buf);
    snprintf(path, sizeof path, "/proc/%d/environ", pid);
    n = slurp(path, buf, sizeof buf);
    printf("child's environ has FWE_PROC=1: %d\n", has_var(buf, n, "FWE_PROC=1"));
    snprintf(path, sizeof path, "/proc/%d/limits", pid);
    slurp(path, buf, sizeof buf);
    printf("child's limits: %d\n", strstr(buf, "Max open files") != 0);
    snprintf(path, sizeof path, "/proc/%d/mountinfo", pid);
    long a = slurp(path, buf, sizeof buf);
    static char mine[65536];
    long b = slurp("/proc/self/mountinfo", mine, sizeof mine);
    printf("child's mountinfo is ours: %d\n", a > 0 && a == b && memcmp(buf, mine, a) == 0);
    write(done[1], "x", 1);
    reap(pid);
    /* One that cannot trace this process. */
    pid_t me = getpid();
    fflush(0);
    pid = fork();
    if (pid == 0) {
        setgid(1000);
        setuid(1000);
        const char *files[] = {"environ", "maps", "io", "limits"};
        for (int i = 0; i < 4; i++) {
            snprintf(path, sizeof path, "/proc/%d/%s", me, files[i]);
            long r = slurp(path, buf, sizeof buf);
            printf("unprivileged %s: %ld\n", files[i], r < 0 ? -r : 0);
        }
        snprintf(path, sizeof path, "/proc/%d/cwd", me);
        printf("unprivileged cwd: %d\n", readlink(path, buf, sizeof buf) < 0 ? errno : 0);
        fflush(0);
        _exit(0);
    }
    reap(pid);
}

static void net(void) {
    long n = readlink("/proc/net", buf, sizeof buf - 1);
    buf[n < 0 ? 0 : n] = 0;
    printf("/proc/net: %s\n", buf);
    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0) {
        printf("unshare: %d\n", errno);
        return;
    }
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    memcpy(ifr.name, "lo", 3);
    ioctl(s, SIOCGIFFLAGS, &ifr);
    ifr.flags |= IFF_UP;
    ioctl(s, SIOCSIFFLAGS, &ifr);
    struct sockaddr_in a = {AF_INET, 0x901f, 0x0100007f, {0}};
    printf("listen: %d\n", bind(s, &a, sizeof a) == 0 && listen(s, 4) == 0);
    slurp("/proc/net/tcp", buf, sizeof buf);
    printf("tcp lists it: %d\n", strstr(buf, ": 0100007F:1F90 00000000:0000 0A ") != 0);
    struct sockaddr_un u;
    memset(&u, 0, sizeof u);
    u.family = AF_UNIX;
    snprintf(u.path, sizeof u.path, "/tmp/procnet-%d", getpid());
    int us = socket(AF_UNIX, SOCK_STREAM, 0);
    unlink(u.path);
    bind(us, &u, sizeof u);
    listen(us, 1);
    slurp("/proc/net/unix", buf, sizeof buf);
    printf("unix lists it: %d\n", strstr(buf, u.path) != 0);
    unlink(u.path);
    slurp("/proc/net/dev", buf, sizeof buf);
    printf("dev: %d\n", strstr(buf, "    lo: ") != 0);
    slurp("/proc/net/if_inet6", buf, sizeof buf);
    printf("if_inet6: %s", buf);
    slurp("/proc/net/route", buf, sizeof buf);
    printf("route: %s", buf);
}

/* A directory's link count, by newfstatat (Linux arm64's `struct stat`
 * has it at byte 20). */
static unsigned links(const char *path) {
    unsigned char st[128];
    if (syscall(79, -100, path, st, 0) != 0) return 0;
    return *(unsigned *)(st + 20);
}

static volatile int go_on;

static void *waits(void *arg) {
    (void)arg;
    while (!go_on) usleep(1000);
    return 0;
}

static void counts(void) {
    printf("task links, one thread: %u\n", links("/proc/self/task/"));
    pthread_t t;
    pthread_create(&t, 0, waits, 0);
    printf("task links, two threads: %u\n", links("/proc/self/task/"));
    go_on = 1;
    pthread_join(t, 0);
    char path[64];
    snprintf(path, sizeof path, "/proc/%d", getpid());
    printf("process directory has subdirectories: %d\n", links(path) > 2);
}

int main(void) {
    counts();
    memory();
    own();
    hostname();
    other();
    net();
    fflush(0);
    return 0;
}
