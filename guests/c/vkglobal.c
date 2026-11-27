/* A program that has the Vulkan loader among its libraries, as WebKitGTK
 * and Mesa's drivers do: the loader's own vkGetDeviceProcAddr is then in
 * the process's global scope. It makes an instance and a device through
 * fwe's driver and takes the device's queue: the driver's functions stay
 * its own (the loader's in their place would call themselves for ever).
 *
 * Built freestanding against musl's shared library, run in an Alpine root
 * with its loader. */
int printf(const char *fmt, ...);
void *dlopen(const char *path, int flags);
void *dlsym(void *lib, const char *name);
char *dlerror(void);

#define RTLD_NOW 2
#define RTLD_GLOBAL 0x100

typedef void (*vk_fn)(void);
typedef vk_fn (*gipa_t)(void *instance, const char *name);
typedef vk_fn (*gdpa_t)(void *device, const char *name);

struct instance_info {
    int type;
    const void *next;
    unsigned flags;
    const void *app;
    unsigned layers;
    const char *const *layer_names;
    unsigned extensions;
    const char *const *extension_names;
};
struct queue_info {
    int type;
    const void *next;
    unsigned flags, family, count;
    const float *priorities;
};
struct device_info {
    int type;
    const void *next;
    unsigned flags, queues;
    const struct queue_info *queue_infos;
    unsigned layers;
    const char *const *layer_names;
    unsigned extensions;
    const char *const *extension_names;
    const void *features;
};

int main(void) {
    void *lib = dlopen("libvulkan.so.1", RTLD_NOW | RTLD_GLOBAL);
    if (!lib) {
        printf("loader: %s\n", dlerror());
        return 1;
    }
    gipa_t gipa = (gipa_t)dlsym(lib, "vkGetInstanceProcAddr");
    int (*create_instance)(const struct instance_info *, const void *, void **) =
        (int (*)(const struct instance_info *, const void *, void **))gipa(0, "vkCreateInstance");
    struct instance_info ii = {1, 0, 0, 0, 0, 0, 0, 0};
    void *instance = 0;
    printf("instance: %d\n", create_instance(&ii, 0, &instance));
    int (*enumerate)(void *, unsigned *, void **) =
        (int (*)(void *, unsigned *, void **))gipa(instance, "vkEnumeratePhysicalDevices");
    unsigned n = 1;
    void *gpu = 0;
    int r = enumerate(instance, &n, &gpu);
    printf("physical device: %s\n", (r == 0 || r == 5) && n >= 1 ? "found" : "none");
    int (*create_device)(void *, const struct device_info *, const void *, void **) =
        (int (*)(void *, const struct device_info *, const void *, void **))gipa(instance, "vkCreateDevice");
    float priority = 1;
    struct queue_info qi = {2, 0, 0, 0, 1, &priority};
    struct device_info di = {3, 0, 0, 1, &qi, 0, 0, 0, 0, 0};
    void *device = 0;
    printf("device: %d\n", create_device(gpu, &di, 0, &device));
    gdpa_t gdpa = (gdpa_t)gipa(instance, "vkGetDeviceProcAddr");
    void (*get_queue)(void *, unsigned, unsigned, void **) =
        (void (*)(void *, unsigned, unsigned, void **))gdpa(device, "vkGetDeviceQueue");
    void *queue = 0;
    get_queue(device, 0, 0, &queue);
    printf("queue: %s\n", queue ? "taken" : "none");
    void (*destroy_device)(void *, const void *) = (void (*)(void *, const void *))gdpa(device, "vkDestroyDevice");
    destroy_device(device, 0);
    return 0;
}
