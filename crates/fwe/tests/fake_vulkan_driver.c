/* A Mac Vulkan driver for fwe's tests, which does what Metal does under
 * MoltenVK that Vulkan's mock driver does not: making a device opens a
 * descriptor (read-write, not close-on-exec, as Metal's caches are) and
 * starts a thread of its own, which takes signals (its mask unblocked, as
 * a thread started later in a guest's call has the guest's), and raises
 * SIGUSR1 on itself a second later. One physical device; fences that never
 * signal. Built by the tests (clang -dynamiclib), for macOS. */
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

typedef void (*fn)(void);
typedef int32_t result;

#define EXPORT __attribute__((visibility("default")))

/* Dispatchable objects: a first word for a loader, as drivers keep. */
struct object {
    uintptr_t loader;
};

static struct object physical_device;

static result create_instance(const void *info, const void *allocator, void **instance) {
    (void)info, (void)allocator;
    *instance = calloc(1, sizeof(struct object));
    return 0;
}

static void destroy_instance(void *instance, const void *allocator) {
    (void)allocator;
    free(instance);
}

static result enumerate_instance_version(uint32_t *version) {
    *version = (1u << 22) | (3u << 12);
    return 0;
}

static result no_extensions(const char *layer, uint32_t *count, void *props) {
    (void)layer, (void)props;
    *count = 0;
    return 0;
}

static result no_device_extensions(void *pd, const char *layer, uint32_t *count, void *props) {
    (void)pd;
    return no_extensions(layer, count, props);
}

static result enumerate_physical_devices(void *instance, uint32_t *count, void **devices) {
    (void)instance;
    if (devices) {
        if (*count < 1) return 5; /* VK_INCOMPLETE */
        devices[0] = &physical_device;
    }
    *count = 1;
    return 0;
}

static void *raiser(void *arg) {
    (void)arg;
    sigset_t none;
    sigemptyset(&none);
    pthread_sigmask(SIG_SETMASK, &none, 0);
    sleep(1);
    pthread_kill(pthread_self(), SIGUSR1);
    for (;;) pause();
    return 0;
}

static result create_device(void *pd, const void *info, const void *allocator, void **device) {
    (void)pd, (void)info, (void)allocator;
    if (open("/dev/null", O_RDWR) < 0) return -3;
    pthread_t t;
    if (pthread_create(&t, 0, raiser, 0) != 0) return -3;
    pthread_detach(t);
    *device = calloc(1, sizeof(struct object));
    return 0;
}

static void destroy_device(void *device, const void *allocator) {
    (void)allocator;
    free(device);
}

static result create_fence(void *device, const void *info, const void *allocator, uint64_t *fence) {
    (void)device, (void)info, (void)allocator;
    *fence = 1;
    return 0;
}

static result wait_for_fences(void *device, uint32_t n, const uint64_t *fences, uint32_t all, uint64_t timeout) {
    (void)device, (void)n, (void)fences, (void)all;
    struct timespec t = {(time_t)(timeout / 1000000000u), (long)(timeout % 1000000000u)};
    nanosleep(&t, 0);
    return 2; /* VK_TIMEOUT: never signalled */
}

static fn lookup(const char *name);

static fn get_device_proc_addr(void *device, const char *name) {
    (void)device;
    return lookup(name);
}

static const struct {
    const char *name;
    fn f;
} table[] = {
    {"vkCreateInstance", (fn)create_instance},
    {"vkDestroyInstance", (fn)destroy_instance},
    {"vkEnumerateInstanceVersion", (fn)enumerate_instance_version},
    {"vkEnumerateInstanceExtensionProperties", (fn)no_extensions},
    {"vkEnumerateDeviceExtensionProperties", (fn)no_device_extensions},
    {"vkEnumeratePhysicalDevices", (fn)enumerate_physical_devices},
    {"vkCreateDevice", (fn)create_device},
    {"vkDestroyDevice", (fn)destroy_device},
    {"vkGetDeviceProcAddr", (fn)get_device_proc_addr},
    {"vkCreateFence", (fn)create_fence},
    {"vkWaitForFences", (fn)wait_for_fences},
};

static fn lookup(const char *name) {
    for (size_t i = 0; i < sizeof table / sizeof table[0]; i++)
        if (!strcmp(name, table[i].name)) return table[i].f;
    return 0;
}

EXPORT result vk_icdNegotiateLoaderICDInterfaceVersion(uint32_t *version) {
    if (*version > 7) *version = 7;
    return 0;
}

EXPORT fn vk_icdGetInstanceProcAddr(void *instance, const char *name) {
    (void)instance;
    return lookup(name);
}
