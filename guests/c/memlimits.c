/* Memory a program cannot have and the limits on what it can hold, as
 * Linux sets them: huge pages from an empty pool (MAP_HUGETLB,
 * SHM_HUGETLB, vm.nr_hugepages, /proc/meminfo), SHM_LOCK charging a
 * segment to its locker's RLIMIT_MEMLOCK, MADV_COLD and MADV_PAGEOUT
 * refusing locked memory; and a cgroup's files: its creator's, pids.max
 * with no suffix, cgroup.subtree_control refusing a controller Linux
 * lacks. Runs as root, in a cgroup of its own that it removes.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

#include "kapi.h"

int chown(const char *path, unsigned uid, unsigned gid);

#define PROT_RW 3
#define MAP_PRIVATE 0x02
#define MAP_SHARED 0x01
#define MAP_ANONYMOUS 0x20
#define MAP_NORESERVE 0x4000
#define MAP_HUGETLB 0x40000
#define MAP_FAILED ((void *)-1)
#define IPC_PRIVATE 0
#define IPC_CREAT 01000
#define IPC_RMID 0
#define IPC_STAT 2
#define SHM_HUGETLB 04000
#define SHM_NORESERVE 010000
#define SHM_LOCK 11
#define SHM_UNLOCK 12
#define SHM_LOCKED 02000
#define MADV_COLD 20
#define MADV_PAGEOUT 21
#define RLIMIT_MEMLOCK 8

#define SYS_SHMGET 194
#define SYS_SHMCTL 195
#define SYS_MADVISE 233
#define SYS_MLOCK 228
#define SYS_MUNLOCK 229
#define SYS_SETRLIMIT 164
#define SYS_SETGROUPS 159
#define SYS_SETRESGID 149
#define SYS_SETRESUID 147
#define SYS_FSTATAT 79

#define PAGE 4096UL
#define HUGE (2UL << 20)

static char buf[8192];

/* 0, or the errno a call that returned -1 left. */
static int e(long r) {
    return r == -1 ? errno : 0;
}

static int shmget(unsigned long size, int flags) {
    return syscall(SYS_SHMGET, IPC_PRIVATE, size, IPC_CREAT | 0600 | flags);
}

static int shmctl(int id, int cmd) {
    return e(syscall(SYS_SHMCTL, id, cmd, 0));
}

/* A segment's mode, as IPC_STAT shows it. */
static unsigned shm_mode(int id) {
    unsigned char ds[112];
    syscall(SYS_SHMCTL, id, IPC_STAT, ds);
    return *(unsigned *)(ds + 20);
}

static void become(unsigned id) {
    syscall(SYS_SETGROUPS, 0, 0);
    syscall(SYS_SETRESGID, id, id, id);
    syscall(SYS_SETRESUID, id, id, id);
}

static void huge_pages(void) {
    void *p = mmap(0, HUGE, PROT_RW, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
    printf("MAP_HUGETLB: %d\n", p == MAP_FAILED ? errno : 0);
    p = mmap(0, HUGE, PROT_RW, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_NORESERVE, -1, 0);
    printf("MAP_HUGETLB|MAP_NORESERVE: %d\n", p == MAP_FAILED ? errno : 0);
    if (p != MAP_FAILED) {
        munmap(p, HUGE);
    }
    printf("SHM_HUGETLB: %d\n", e(shmget(HUGE, SHM_HUGETLB)));
    slurp("/proc/sys/vm/nr_hugepages", buf, sizeof buf);
    printf("nr_hugepages: %s", buf);
    printf("nr_hugepages = 8: %d\n", put("/proc/sys/vm/nr_hugepages", "8"));
    slurp("/proc/sys/vm/nr_hugepages", buf, sizeof buf);
    printf("nr_hugepages: %s", buf);
    slurp("/proc/meminfo", buf, sizeof buf);
    char *t = strstr(buf, "HugePages_Total:");
    char *r = strstr(buf, "HugePages_Rsvd:");
    printf("meminfo: total %ld, reserved %ld\n", t ? strtol(t + 16, 0, 10) : -1,
           r ? strtol(r + 15, 0, 10) : -1);
}

static void shm_lock(void) {
    int id = shmget(3 * PAGE, 0);
    printf("SHM_LOCK by root: %d, ", shmctl(id, SHM_LOCK));
    printf("shown locked: %d, ", (shm_mode(id) & SHM_LOCKED) != 0);
    printf("SHM_UNLOCK: %d, ", shmctl(id, SHM_UNLOCK));
    printf("shown locked: %d\n", (shm_mode(id) & SHM_LOCKED) != 0);
    shmctl(id, IPC_RMID);
    fflush(0);
    pid_t pid = fork();
    if (pid == 0) {
        become(1000);
        unsigned long lim[2] = {2 * PAGE, 2 * PAGE};
        syscall(SYS_SETRLIMIT, RLIMIT_MEMLOCK, lim);
        int three = shmget(3 * PAGE, 0), two = shmget(2 * PAGE, 0), one = shmget(PAGE, 0);
        printf("user: 3 pages past RLIMIT_MEMLOCK: %d, ", shmctl(three, SHM_LOCK));
        printf("2 pages: %d, again: %d, ", shmctl(two, SHM_LOCK), shmctl(two, SHM_LOCK));
        printf("1 more: %d, ", shmctl(one, SHM_LOCK));
        printf("after unlocking 2: %d\n", (shmctl(two, SHM_UNLOCK), shmctl(one, SHM_LOCK)));
        lim[0] = lim[1] = 0;
        syscall(SYS_SETRLIMIT, RLIMIT_MEMLOCK, lim);
        printf("user: with RLIMIT_MEMLOCK 0: %d\n", shmctl(two, SHM_LOCK));
        shmctl(three, IPC_RMID);
        shmctl(two, IPC_RMID);
        shmctl(one, IPC_RMID);
        fflush(0);
        _exit(0);
    }
    reap(pid);
}

static void paging_out(void) {
    char *p = mmap(0, 2 * PAGE, PROT_RW, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("MADV_COLD: %d, ", e(syscall(SYS_MADVISE, p, 2 * PAGE, MADV_COLD)));
    syscall(SYS_MLOCK, p + PAGE, PAGE);
    printf("locked: %d, ", e(syscall(SYS_MADVISE, p, 2 * PAGE, MADV_COLD)));
    printf("MADV_PAGEOUT locked: %d, ", e(syscall(SYS_MADVISE, p, 2 * PAGE, MADV_PAGEOUT)));
    syscall(SYS_MUNLOCK, p + PAGE, PAGE);
    printf("unlocked: %d\n", e(syscall(SYS_MADVISE, p, 2 * PAGE, MADV_PAGEOUT)));
    munmap(p, 2 * PAGE);
}

/* The owner of `path`, as "uid:gid". */
static void owner(const char *path) {
    unsigned char st[128];
    if (syscall(SYS_FSTATAT, -100, path, st, 0) != 0) {
        printf("errno %d", errno);
        return;
    }
    printf("%u:%u", *(unsigned *)(st + 24), *(unsigned *)(st + 28));
}

static void cgroups(void) {
    char top[128], p[256];
    snprintf(top, sizeof top, "/sys/fs/cgroup/fwe-memlimits-%d", getpid());
    put("/sys/fs/cgroup/cgroup.subtree_control", "+pids +memory");
    mkdir(top, 0755);
    snprintf(p, sizeof p, "%s/pids.max", top);
    int k = put(p, "1K"), ten = put(p, "10");
    slurp(p, buf, sizeof buf);
    printf("pids.max 1K: %d, 10: %d, reads %s", k, ten, buf);
    snprintf(p, sizeof p, "%s/memory.max", top);
    put(p, "5000");
    slurp(p, buf, sizeof buf);
    printf("memory.max 5000 reads %s", buf);
    snprintf(p, sizeof p, "%s/cgroup.subtree_control", top);
    printf("subtree_control +bogus: %d, +pids +bogus: %d, +pids: %d, -cpu: %d\n",
           put(p, "+bogus"), put(p, "+pids +bogus"), put(p, "+pids"), put(p, "-cpu"));
    chown(top, 1000, 1000);
    fflush(0);
    pid_t pid = fork();
    if (pid == 0) {
        become(1000);
        snprintf(p, sizeof p, "%s/d", top);
        printf("mkdir as 1000: %d\n", mkdir(p, 0755) == 0 ? 0 : errno);
        printf("d/cgroup.procs: ");
        snprintf(p, sizeof p, "%s/d/cgroup.procs", top);
        owner(p);
        printf(", d/pids.max: ");
        snprintf(p, sizeof p, "%s/d/pids.max", top);
        owner(p);
        printf("\n");
        fflush(0);
        _exit(0);
    }
    reap(pid);
    snprintf(p, sizeof p, "%s/d", top);
    rmdir(p);
    rmdir(top);
}

int main(void) {
    huge_pages();
    shm_lock();
    paging_out();
    cgroups();
    fflush(0);
    return 0;
}
