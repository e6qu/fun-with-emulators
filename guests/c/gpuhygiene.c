/* What the Mac's Vulkan driver does in fwe's process stays out of the
 * program's way, on a driver that acts as Metal does (the tests' fake
 * driver): the descriptor it opens as a device is made is not among the
 * program's; a signal the host gives a thread of the driver's reaches the
 * program's thread, waiting in poll; a wait on a fence that never
 * signals ends at its timeout. With an argument, the driver is handed a
 * bad pointer to write: the process ends with SIGSEGV.
 *
 * Built freestanding and linked against the target libc's shared library
 * (no system headers), as the other dynamic guests. */

#include "kapi.h"
#include "../../driver/vulkan/generated.h"

typedef void (*handler_t)(int);
handler_t signal(int sig, handler_t handler);
struct pollfd {
    int fd;
    short events, revents;
};
int poll(struct pollfd *fds, unsigned long n, int timeout);
struct dirent {
    unsigned long ino;
    long off;
    unsigned short reclen;
    unsigned char type;
    char name[256];
};
void *opendir(const char *path);
struct dirent *readdir(void *dir);
int closedir(void *dir);
struct timespec {
    long sec, nsec;
};
int clock_gettime(int clock, struct timespec *ts);

#define SIGUSR1 10
#define EINTR 4
#define POLLIN 1

typedef unsigned int u32;
typedef unsigned long u64;

struct call {
    u32 command, words;
    u64 args, result;
};

static int device_fd;

/* Command `command` with words `w`: its result (a VkResult), or -1000 if
 * the ioctl failed. */
static long vk(u32 command, u64 *w, u32 n) {
    struct call c = {command, n, (u64)w, 0};
    if (ioctl(device_fd, FWE_VK_IOCTL_CALL, &c) != 0) return -1000;
    return (long)(int)c.result;
}

/* The program's descriptors, as their numbers. */
static void descriptors(char *out, size_t size) {
    void *d = opendir("/proc/self/fd");
    size_t at = 0;
    out[0] = 0;
    for (struct dirent *e; d && (e = readdir(d));) {
        if (e->name[0] == '.') continue;
        at += snprintf(out + at, size - at, "%s ", e->name);
    }
    if (d) closedir(d);
}

static volatile int took;
static void on_usr1(int sig) {
    (void)sig;
    took = 1;
}

static long now_ms(void) {
    struct timespec t;
    clock_gettime(1, &t);
    return t.sec * 1000 + t.nsec / 1000000;
}

int main(int argc, char **argv) {
    (void)argv;
    device_fd = open("/dev/fwe-gpu", O_RDWR | O_CLOEXEC);
    u64 info[8] = {1}; /* VkInstanceCreateInfo */
    u64 instance = 0;
    u64 ci[3] = {(u64)info, 0, (u64)&instance};
    if (vk(FWE_VK_CMD_vkCreateInstance, ci, 3) != 0) {
        printf("no instance\n");
        return 1;
    }
    if (argc > 1) {
        u64 bad[3] = {instance, 0x10, 0};
        vk(FWE_VK_CMD_vkEnumeratePhysicalDevices, bad, 3);
        printf("the driver wrote through a bad pointer\n");
        return 1;
    }
    u32 count = 1;
    u64 pd = 0;
    u64 en[3] = {instance, (u64)&count, (u64)&pd};
    vk(FWE_VK_CMD_vkEnumeratePhysicalDevices, en, 3);
    signal(SIGUSR1, on_usr1);
    char before[256], after[256];
    descriptors(before, sizeof before);
    u64 dinfo[9] = {3}; /* VkDeviceCreateInfo */
    u64 device = 0;
    u64 cd[4] = {pd, (u64)dinfo, 0, (u64)&device};
    if (vk(FWE_VK_CMD_vkCreateDevice, cd, 4) != 0) {
        printf("no device\n");
        return 1;
    }
    descriptors(after, sizeof after);
    if (!strcmp(before, after))
        printf("descriptors: the program's own\n");
    else
        printf("descriptors: before %s, after %s\n", before, after);
    fflush(0);

    /* The driver's thread takes SIGUSR1 a second after the device was
     * made: this thread, waiting, is to take it. */
    int p[2];
    pipe(p);
    struct pollfd pf = {p[0], POLLIN, 0};
    long began = now_ms();
    int n = poll(&pf, 1, 20000);
    int e = errno;
    if (n < 0 && e == EINTR && took)
        printf("signal: taken while waiting\n");
    else
        printf("signal: poll %d errno %d handler %d after %ld ms\n", n, e, took, now_ms() - began);

    /* A wait for a fence the driver never signals ends at its timeout:
     * 30 ms on, as the library's stub gives it (an absolute
     * CLOCK_MONOTONIC deadline). */
    u64 fence = 0, finfo[3] = {8};
    u64 cf[4] = {device, (u64)finfo, 0, (u64)&fence};
    vk(FWE_VK_CMD_vkCreateFence, cf, 4);
    struct timespec t;
    clock_gettime(1, &t);
    began = now_ms();
    u64 deadline = (u64)t.sec * 1000000000u + (u64)t.nsec + 30000000u;
    u64 wf[5] = {device, 1, (u64)&fence, 1, deadline};
    long r = vk(FWE_VK_CMD_vkWaitForFences, wf, 5);
    long took_ms = now_ms() - began;
    printf("fence: %s\n", r == 2 && took_ms >= 25 && took_ms < 5000 ? "timed out" : "wrong");
    if (r != 2 || took_ms < 25 || took_ms >= 5000) printf("fence: result %ld after %ld ms\n", r, took_ms);
    return 0;
}
