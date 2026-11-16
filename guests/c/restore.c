/* What checkpoint/restore tools ask of the kernel (CONFIG_CHECKPOINT_RESTORE):
 * PR_GET_TID_ADDRESS, TFD_IOC_SET_TICKS, kernel.ns_last_pid in a pid
 * namespace, and PR_SET_MM (the layout's size, a new argument range that
 * /proc/self/cmdline then shows, the program file and auxiliary vector,
 * and its checks). It prints what it observed. */
#include "kapi.h"

#define PR_SET_MM 35
#define PR_SET_MM_START_CODE 1
#define PR_SET_MM_ARG_START 8
#define PR_SET_MM_ARG_END 9
#define PR_SET_MM_AUXV 12
#define PR_SET_MM_EXE_FILE 13
#define PR_SET_MM_MAP_SIZE 15
#define PR_GET_TID_ADDRESS 40
#define TFD_IOC_SET_TICKS 0x40085400
#define SYS_set_tid_address 96
#define SYS_timerfd_create 85
#define CLOCK_MONOTONIC 1
#define TFD_NONBLOCK 04000

/* A new command line, in the program's data. */
static char title[] = "renamed\0by prctl";

static long last_pid(void) {
    char buf[32];
    if (slurp("/proc/sys/kernel/ns_last_pid", buf, sizeof buf) < 0) {
        return -errno;
    }
    return strtol(buf, 0, 10);
}

int main(void) {
    int word = 0;
    syscall(SYS_set_tid_address, &word);
    unsigned long got = 0;
    int r = prctl(PR_GET_TID_ADDRESS, &got, 0, 0, 0);
    printf("PR_GET_TID_ADDRESS: %d, the word set %d\n", r, got == (unsigned long)&word);

    int t = syscall(SYS_timerfd_create, CLOCK_MONOTONIC, TFD_NONBLOCK);
    unsigned long long ticks = 5, v = 0;
    r = ioctl(t, TFD_IOC_SET_TICKS, &ticks);
    long n = read(t, &v, 8);
    long again = read(t, &v, 8) < 0 ? -errno : 0;
    ticks = 0;
    int zero = ioctl(t, TFD_IOC_SET_TICKS, &ticks) < 0 ? -errno : 0;
    printf("TFD_IOC_SET_TICKS: %d, read %ld of %llu, then %ld; 0 ticks %d\n", r, n, v, again,
           zero);
    close(t);

    printf("host's ns_last_pid read: %d\n", last_pid() > 0);
    int set = put("/proc/sys/kernel/ns_last_pid", "100");
    printf("set in the host's namespace: %d\n", set);
    fflush(0);
    unshare(CLONE_NEWPID);
    pid_t child = fork();
    if (child == 0) {
        /* Pid 1 of a new namespace: the next pid is after the one set. */
        long before = last_pid();
        int w = put("/proc/sys/kernel/ns_last_pid", "41");
        long after = last_pid();
        pid_t grandchild = fork();
        if (grandchild == 0) {
            _exit(getpid() == 42 ? 0 : 1);
        }
        int st = reap(grandchild);
        int bad = put("/proc/sys/kernel/ns_last_pid", "-1");
        setuid(1000);
        int denied = put("/proc/sys/kernel/ns_last_pid", "50");
        printf("in a new namespace: last %ld, set %d, then %ld, next pid 42 %d, -1 %d, "
               "a user %d\n",
               before, w, after, st == 0, bad, denied);
        fflush(0);
        _exit(0);
    }
    reap(child);

    unsigned size = 0;
    r = prctl(PR_SET_MM, PR_SET_MM_MAP_SIZE, &size, 0, 0);
    printf("PR_SET_MM_MAP_SIZE: %d, %u\n", r, size);
    int start = prctl(PR_SET_MM, PR_SET_MM_ARG_START, title, 0, 0);
    int end = prctl(PR_SET_MM, PR_SET_MM_ARG_END, title + sizeof title, 0, 0);
    char line[64];
    long len = slurp("/proc/self/cmdline", line, sizeof line);
    printf("arguments moved: %d %d, cmdline \"%s\" \"%s\" (%ld bytes)\n", start, end, line,
           line + strlen(line) + 1, len);
    int low = prctl(PR_SET_MM, PR_SET_MM_START_CODE, 0x1000, 0, 0) < 0 ? -errno : 0;
    int extra = prctl(PR_SET_MM, PR_SET_MM_ARG_END, title, 1, 0) < 0 ? -errno : 0;
    /* A program in the root (this one is outside it). */
    int exe = open("/lib/ld-linux-aarch64.so.1", O_RDONLY);
    int busy = prctl(PR_SET_MM, PR_SET_MM_EXE_FILE, exe, 0, 0) < 0 ? -errno : 0;
    unsigned long auxv[52] = {0};
    int big = prctl(PR_SET_MM, PR_SET_MM_AUXV, auxv, sizeof auxv, 0) < 0 ? -errno : 0;
    /* AT_PAGESZ 4096, then AT_NULL. */
    auxv[0] = 6;
    auxv[1] = 4096;
    int small = prctl(PR_SET_MM, PR_SET_MM_AUXV, auxv, 4 * sizeof auxv[0], 0);
    unsigned long shown[8] = {0};
    int fd = open("/proc/self/auxv", O_RDONLY);
    long shown_len = read(fd, shown, sizeof shown);
    close(fd);
    printf("below mmap_min_addr %d, extra argument %d, program file mapped %d, auxv too big "
           "%d, auxv set %d: %ld bytes, AT_PAGESZ %lu\n",
           low, extra, busy, big, small, shown_len, shown[1]);
    fflush(0);
    child = fork();
    if (child == 0) {
        setuid(1000);
        int denied = prctl(PR_SET_MM, PR_SET_MM_ARG_START, title, 0, 0) < 0 ? -errno : 0;
        printf("a user's PR_SET_MM: %d\n", denied);
        fflush(0);
        _exit(0);
    }
    reap(child);
    return 0;
}
