/* A Vulkan submission's round trip: an empty command buffer submitted to
 * the first device's first queue with a fence, the fence waited for and
 * reset, N times; the microseconds each took, as the last word printed.
 *
 *     vkbench N [LIBVULKAN]
 *
 * The same source is built for Linux (run under fwe, on Mesa's Venus
 * driver on fwe's GPU device) and for macOS (run natively on MoltenVK),
 * the loader opened by name (LIBVULKAN; Linux's soname by default), so
 * neither build links it. */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <vulkan/vulkan.h>

#ifndef VK_KHR_portability_enumeration
#define VK_KHR_PORTABILITY_ENUMERATION_EXTENSION_NAME "VK_KHR_portability_enumeration"
#define VK_INSTANCE_CREATE_ENUMERATE_PORTABILITY_BIT_KHR 0x00000001
#endif

static void check(VkResult r, const char *what) {
    if (r != VK_SUCCESS) {
        fprintf(stderr, "vkbench: %s: %d\n", what, r);
        exit(1);
    }
}

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec / 1e9;
}

/* Whether `name` is among the `n` extensions in `ext`. */
static int has(const VkExtensionProperties *ext, uint32_t n, const char *name) {
    for (uint32_t i = 0; i < n; i++)
        if (!strcmp(ext[i].extensionName, name)) return 1;
    return 0;
}

int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 1000;
    const char *libname = argc > 2 ? argv[2] : "libvulkan.so.1";
    void *lib = dlopen(libname, RTLD_NOW);
    if (!lib) {
        fprintf(stderr, "vkbench: %s\n", dlerror());
        return 1;
    }
    PFN_vkGetInstanceProcAddr gipa = (PFN_vkGetInstanceProcAddr)dlsym(lib, "vkGetInstanceProcAddr");
#define GLOBAL(name) PFN_##name name = (PFN_##name)gipa(NULL, #name)
#define INSTANCE(name) PFN_##name name = (PFN_##name)gipa(inst, #name)
    GLOBAL(vkCreateInstance);
    GLOBAL(vkEnumerateInstanceExtensionProperties);

    /* MoltenVK is a portability implementation: listed only when asked. */
    uint32_t next = 0;
    vkEnumerateInstanceExtensionProperties(NULL, &next, NULL);
    VkExtensionProperties *iext = calloc(next ? next : 1, sizeof *iext);
    vkEnumerateInstanceExtensionProperties(NULL, &next, iext);
    int portable = has(iext, next, VK_KHR_PORTABILITY_ENUMERATION_EXTENSION_NAME);
    const char *portability = VK_KHR_PORTABILITY_ENUMERATION_EXTENSION_NAME;
    VkApplicationInfo app = {.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO,
                             .pApplicationName = "vkbench",
                             .apiVersion = VK_API_VERSION_1_1};
    VkInstanceCreateInfo ici = {.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
                                .pApplicationInfo = &app,
                                .flags = portable ? VK_INSTANCE_CREATE_ENUMERATE_PORTABILITY_BIT_KHR : 0,
                                .enabledExtensionCount = portable ? 1 : 0,
                                .ppEnabledExtensionNames = &portability};
    VkInstance inst;
    check(vkCreateInstance(&ici, NULL, &inst), "vkCreateInstance");
    INSTANCE(vkEnumeratePhysicalDevices);
    INSTANCE(vkGetPhysicalDeviceProperties);
    INSTANCE(vkGetPhysicalDeviceQueueFamilyProperties);
    INSTANCE(vkEnumerateDeviceExtensionProperties);
    INSTANCE(vkCreateDevice);
    INSTANCE(vkGetDeviceProcAddr);

    uint32_t count = 1;
    VkPhysicalDevice phys;
    VkResult r = vkEnumeratePhysicalDevices(inst, &count, &phys);
    if ((r != VK_SUCCESS && r != VK_INCOMPLETE) || count == 0) {
        fprintf(stderr, "vkbench: no Vulkan device (%d)\n", r);
        return 1;
    }
    VkPhysicalDeviceProperties props;
    vkGetPhysicalDeviceProperties(phys, &props);
    fprintf(stderr, "vkbench: %s\n", props.deviceName);

    uint32_t families = 0;
    vkGetPhysicalDeviceQueueFamilyProperties(phys, &families, NULL);
    VkQueueFamilyProperties *fam = calloc(families, sizeof *fam);
    vkGetPhysicalDeviceQueueFamilyProperties(phys, &families, fam);
    uint32_t family = 0;
    while (family < families && !(fam[family].queueFlags & VK_QUEUE_GRAPHICS_BIT)) family++;
    if (family == families) {
        fprintf(stderr, "vkbench: no graphics queue\n");
        return 1;
    }

    /* A portability device must have its subset enabled. */
    uint32_t dnext = 0;
    vkEnumerateDeviceExtensionProperties(phys, NULL, &dnext, NULL);
    VkExtensionProperties *dext = calloc(dnext ? dnext : 1, sizeof *dext);
    vkEnumerateDeviceExtensionProperties(phys, NULL, &dnext, dext);
    const char *subset = "VK_KHR_portability_subset";
    int needs_subset = has(dext, dnext, subset);
    float priority = 1;
    VkDeviceQueueCreateInfo qci = {.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,
                                   .queueFamilyIndex = family,
                                   .queueCount = 1,
                                   .pQueuePriorities = &priority};
    VkDeviceCreateInfo dci = {.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO,
                              .queueCreateInfoCount = 1,
                              .pQueueCreateInfos = &qci,
                              .enabledExtensionCount = needs_subset ? 1 : 0,
                              .ppEnabledExtensionNames = &subset};
    VkDevice dev;
    check(vkCreateDevice(phys, &dci, NULL, &dev), "vkCreateDevice");
#define DEVICE(name) PFN_##name name = (PFN_##name)vkGetDeviceProcAddr(dev, #name)
    DEVICE(vkGetDeviceQueue);
    DEVICE(vkCreateCommandPool);
    DEVICE(vkAllocateCommandBuffers);
    DEVICE(vkBeginCommandBuffer);
    DEVICE(vkEndCommandBuffer);
    DEVICE(vkCreateFence);
    DEVICE(vkQueueSubmit);
    DEVICE(vkWaitForFences);
    DEVICE(vkResetFences);

    VkQueue queue;
    vkGetDeviceQueue(dev, family, 0, &queue);
    VkCommandPoolCreateInfo pci = {.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO,
                                   .queueFamilyIndex = family};
    VkCommandPool pool;
    check(vkCreateCommandPool(dev, &pci, NULL, &pool), "vkCreateCommandPool");
    VkCommandBufferAllocateInfo cai = {.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,
                                       .commandPool = pool,
                                       .level = VK_COMMAND_BUFFER_LEVEL_PRIMARY,
                                       .commandBufferCount = 1};
    VkCommandBuffer cmd;
    check(vkAllocateCommandBuffers(dev, &cai, &cmd), "vkAllocateCommandBuffers");
    VkCommandBufferBeginInfo bi = {.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
    check(vkBeginCommandBuffer(cmd, &bi), "vkBeginCommandBuffer");
    check(vkEndCommandBuffer(cmd), "vkEndCommandBuffer");
    VkFenceCreateInfo fci = {.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO};
    VkFence fence;
    check(vkCreateFence(dev, &fci, NULL, &fence), "vkCreateFence");
    VkSubmitInfo si = {.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO,
                       .commandBufferCount = 1,
                       .pCommandBuffers = &cmd};

    double start = 0;
    for (int i = -10; i < n; i++) {
        if (i == 0) start = now();
        check(vkQueueSubmit(queue, 1, &si, fence), "vkQueueSubmit");
        check(vkWaitForFences(dev, 1, &fence, VK_TRUE, 10ull * 1000 * 1000 * 1000), "vkWaitForFences");
        check(vkResetFences(dev, 1, &fence), "vkResetFences");
    }
    printf("submission round trip (us): %.2f\n", (now() - start) * 1e6 / n);
    return 0;
}
