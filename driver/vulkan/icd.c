/* fwe's Linux Vulkan driver: the loader's interface, the device, and the
 * stubs' calls.
 *
 * A Linux Vulkan loader loads this library from fwe's manifest in
 * /etc/vulkan/icd.d and finds its functions through
 * vk_icdGetInstanceProcAddr. Each Vulkan command is a stub (generated.c)
 * that hands its arguments to fwe with one ioctl on fwe's GPU device,
 * /dev/fwe-gpu; fwe calls the Mac's Vulkan driver with them. */
#include "fwe_vk.h"

/* Linux's system call numbers and values (arm64). */
#define SYS_ioctl 29
#define SYS_openat 56
#define SYS_close 57
#define SYS_clock_gettime 113
#define AT_FDCWD (-100)
#define O_RDWR 02
#define O_CLOEXEC 02000000
#define CLOCK_MONOTONIC 1
#define EBADF 9
#define EINTR 4
#define ENODEV 19

long fwe_syscall(long nr, long a, long b, long c, long d, long e, long f) {
    register long x8 __asm__("x8") = nr;
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x4 __asm__("x4") = e;
    register long x5 __asm__("x5") = f;
    __asm__ volatile("svc 0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                     : "memory");
    return x0;
}

/* The compiler's own calls, which a freestanding library provides. */
void *memcpy(void *dst, const void *src, size_t n) {
    unsigned char *d = dst;
    const unsigned char *s = src;
    while (n--) *d++ = *s++;
    return dst;
}

void *memset(void *dst, int c, size_t n) {
    unsigned char *d = dst;
    while (n--) *d++ = (unsigned char)c;
    return dst;
}

/* The device's descriptor: opened on first use, close-on-exec, and opened
 * again when the one held is not the device's any more (a fork child's
 * copy of its parent's, which fwe refuses with ENODEV, or one the program
 * closed). */
static int device = -1;

static int open_device(int stale) {
    int fd = __atomic_load_n(&device, __ATOMIC_ACQUIRE);
    if (fd >= 0 && fd != stale) return fd;
    long n = fwe_syscall(SYS_openat, AT_FDCWD, (long)"/dev/fwe-gpu", O_RDWR | O_CLOEXEC, 0, 0, 0);
    if (n < 0) return -1;
    int expected = fd;
    if (__atomic_compare_exchange_n(&device, &expected, (int)n, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        /* Not closed: a stale descriptor's number may be the program's own
         * by now. */
        return (int)n;
    }
    /* Another thread opened it first. */
    fwe_syscall(SYS_close, n, 0, 0, 0, 0, 0);
    return expected;
}

uint64_t fwe_vk_call(uint32_t command, const uint64_t *w, uint32_t count, uint64_t failed) {
    struct fwe_vk_call call = {command, count, (uint64_t)(uintptr_t)w, 0};
    int fd = open_device(-1);
    for (int again = 0; fd >= 0;) {
        long r = fwe_syscall(SYS_ioctl, fd, FWE_VK_IOCTL_CALL, (long)&call, 0, 0, 0);
        if (r == 0) return call.result;
        if (r == -EINTR) continue; /* a wait a signal ended: its deadline holds */
        if ((r == -ENODEV || r == -EBADF) && !again++) {
            fd = open_device(fd);
            continue;
        }
        break;
    }
    return failed;
}

int fwe_vk_has(const void *handle, uint32_t command) {
    uint64_t w[2] = {(uint64_t)(uintptr_t)handle, command};
    return fwe_vk_call(FWE_VK_HAS, w, 2, 0) != 0;
}

void *fwe_vk_parent(const void *handle) {
    uint64_t w[1] = {(uint64_t)(uintptr_t)handle};
    return (void *)(uintptr_t)fwe_vk_call(FWE_VK_PARENT, w, 1, 0);
}

uint32_t fwe_vk_queue_family(const void *queue) {
    uint64_t w[1] = {(uint64_t)(uintptr_t)queue};
    return (uint32_t)fwe_vk_call(FWE_VK_QUEUE_FAMILY, w, 1, 0);
}

#define SYS_munmap 215
#define SYS_mmap 222
#define PROT_READ 1
#define PROT_WRITE 2
#define MAP_PRIVATE 2
#define MAP_ANONYMOUS 0x20

void *fwe_alloc(size_t size) {
    long p = fwe_syscall(SYS_mmap, 0, (long)size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return p < 0 && p > -4096 ? 0 : (void *)p;
}

void fwe_free(void *p, size_t size) {
    if (p) fwe_syscall(SYS_munmap, (long)p, (long)size, 0, 0, 0, 0);
}

uint64_t fwe_vk_deadline(uint64_t timeout) {
    if (timeout == UINT64_MAX) return timeout;
    struct {
        long sec, nsec;
    } now = {0, 0};
    fwe_syscall(SYS_clock_gettime, CLOCK_MONOTONIC, (long)&now, 0, 0, 0, 0);
    uint64_t at = (uint64_t)now.sec * 1000000000u + (uint64_t)now.nsec;
    return at + timeout < at ? UINT64_MAX : at + timeout;
}

static int compare(const char *a, const char *b) {
    while (*a && *a == *b) a++, b++;
    return (unsigned char)*a - (unsigned char)*b;
}

/* The entry for command `name`, if the library has a stub for it. */
static const struct fwe_vk_entry *find(const char *name) {
    unsigned lo = 0, hi = fwe_vk_entry_count;
    while (lo < hi) {
        unsigned mid = lo + (hi - lo) / 2;
        int c = compare(name, fwe_vk_entries[mid].name);
        if (c == 0) return &fwe_vk_entries[mid];
        if (c < 0)
            hi = mid;
        else
            lo = mid + 1;
    }
    return 0;
}

FWE_EXPORT fwe_vk_fn vk_icdGetInstanceProcAddr(void *instance, const char *name);
FWE_EXPORT fwe_vk_fn vkGetDeviceProcAddr(void *device, const char *name);

FWE_EXPORT int32_t vk_icdNegotiateLoaderICDInterfaceVersion(uint32_t *version) {
    /* 5: physical devices are the driver's own handles, and the loader
     * asks for functions by name; 7: the driver's functions are only
     * found through vk_icdGetInstanceProcAddr. */
    if (*version < 5) return FWE_VK_INCOMPATIBLE_DRIVER;
    if (*version > 7) *version = 7;
    return FWE_VK_SUCCESS;
}

/* Command `e`'s function for object `handle`, if a program may have it:
 * the driver's command (its stub) or the library's window systems' (wsi.c),
 * where the driver has the command for the object. */
static fwe_vk_fn given(const struct fwe_vk_entry *e, const void *handle) {
    if (e->use == FWE_VK_USE_INTERNAL) return 0;
    if (handle && !fwe_vk_has(handle, e->index)) return 0;
    return e->stub;
}

FWE_EXPORT fwe_vk_fn vk_icdGetPhysicalDeviceProcAddr(void *instance, const char *name) {
    const struct fwe_vk_entry *e = find(name);
    if (!e) return fwe_wsi_proc(name);
    return e->level == FWE_VK_INSTANCE ? given(e, instance) : 0;
}

FWE_EXPORT fwe_vk_fn vk_icdGetInstanceProcAddr(void *instance, const char *name) {
    if (!compare(name, "vkGetInstanceProcAddr") || !compare(name, "vk_icdGetInstanceProcAddr"))
        return (fwe_vk_fn)vk_icdGetInstanceProcAddr;
    if (!compare(name, "vk_icdNegotiateLoaderICDInterfaceVersion"))
        return (fwe_vk_fn)vk_icdNegotiateLoaderICDInterfaceVersion;
    if (!compare(name, "vk_icdGetPhysicalDeviceProcAddr"))
        return (fwe_vk_fn)vk_icdGetPhysicalDeviceProcAddr;
    if (!compare(name, "vkGetDeviceProcAddr")) return (fwe_vk_fn)vkGetDeviceProcAddr;
    const struct fwe_vk_entry *e = find(name);
    if (!e) return instance ? fwe_wsi_proc(name) : 0;
    if (!instance || e->level == FWE_VK_GLOBAL) return e->level == FWE_VK_GLOBAL ? given(e, 0) : 0;
    return given(e, instance);
}

FWE_EXPORT fwe_vk_fn vkGetDeviceProcAddr(void *device, const char *name) {
    if (!compare(name, "vkGetDeviceProcAddr")) return (fwe_vk_fn)vkGetDeviceProcAddr;
    const struct fwe_vk_entry *e = find(name);
    if (!e || e->level != FWE_VK_DEVICE) return 0;
    return given(e, device);
}
