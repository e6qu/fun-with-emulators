/* fwe's GPU device across fork and exec: a fork child of a process using
 * the Mac's Vulkan driver never calls it (its copy of the parent's open and
 * an open of its own fail with ENODEV); after an execve it is a fresh
 * process, whose own open works; the parent's open goes on working. The
 * driver's one ioctl is used directly, its interface from fwe's driver's
 * generated header.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

#include "kapi.h"
#include "../../driver/vulkan/generated.h"

int execv(const char *path, char *const argv[]);

#define ENODEV 19
#define EPROTO 71

typedef unsigned int u32;
typedef unsigned long u64;

struct call {
    u32 command, words;
    u64 args, result;
};

/* vkEnumerateInstanceVersion on device `fd`: 0, or -errno. */
static long version(int fd) {
    if (fd < 0) return -errno;
    u32 v = 0;
    u64 w[1] = {(u64)&v};
    struct call c = {FWE_VK_CMD_vkEnumerateInstanceVersion, 1, (u64)w, 0};
    if (ioctl(fd, FWE_VK_IOCTL_CALL, &c) != 0) return -errno;
    return c.result == 0 && v >= (1u << 22) ? 0 : -EPROTO;
}

static const char *outcome(long r) {
    if (r == 0) return "works";
    if (r == -ENODEV) return "ENODEV";
    static char other[32];
    snprintf(other, sizeof other, "errno %ld", -r);
    return other;
}

static int open_device(void) { return open("/dev/fwe-gpu", O_RDWR | O_CLOEXEC); }

int main(int argc, char **argv) {
    if (argc > 1) {
        printf("exec'd child: its own open %s\n", outcome(version(open_device())));
        return 0;
    }
    int fd = open_device();
    printf("parent: the driver %s\n", outcome(version(fd)));
    fflush(0);
    pid_t pid = fork();
    if (pid == 0) {
        long inherited = version(fd);
        long own = version(open_device());
        printf("child: inherited open %s, own open %s\n", outcome(inherited), outcome(own));
        fflush(0);
        char *again[] = {argv[0], "exec", 0};
        execv("/proc/self/exe", again);
        printf("child: execv: errno %d\n", errno);
        return 1;
    }
    int status = 0;
    waitpid(pid, &status, 0);
    printf("parent: child exit %d, its open %s\n", (status >> 8) & 0xff, outcome(version(fd)));
    return 0;
}
