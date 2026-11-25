/* Vulkan on the first device's first graphics queue, timed:
 *
 *     vkbench submit N [LIBVULKAN]
 *         an empty command buffer submitted with a fence, the fence
 *         waited for and reset, N times: a submission's round trip;
 *     vkbench frame N [LIBVULKAN]
 *         a frame's work, N times: a 300x300 image cleared, copied to
 *         host-visible memory, the fence waited for, and the frame read
 *         there (as a window system that takes frames as copies, Mesa's
 *         software WSI, does with each), its first pixel checked.
 *
 * The microseconds each took, as the last word printed.
 *
 * The same source is built for Linux (run under fwe, on fwe's Vulkan
 * driver, MoltenVK in fwe's process) and for macOS (run natively on MoltenVK),
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

#define SIDE 300

int main(int argc, char **argv) {
    if (argc < 3 || (strcmp(argv[1], "submit") && strcmp(argv[1], "frame"))) {
        fprintf(stderr, "usage: vkbench submit|frame N [LIBVULKAN]\n");
        return 2;
    }
    int frame = !strcmp(argv[1], "frame");
    int n = atoi(argv[2]);
    const char *libname = argc > 3 ? argv[3] : "libvulkan.so.1";
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
    INSTANCE(vkGetPhysicalDeviceMemoryProperties);
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

    /* A portability device needs its subset enabled. */
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
    DEVICE(vkCreateImage);
    DEVICE(vkCreateBuffer);
    DEVICE(vkGetImageMemoryRequirements);
    DEVICE(vkGetBufferMemoryRequirements);
    DEVICE(vkAllocateMemory);
    DEVICE(vkBindImageMemory);
    DEVICE(vkBindBufferMemory);
    DEVICE(vkMapMemory);
    DEVICE(vkCmdPipelineBarrier);
    DEVICE(vkCmdClearColorImage);
    DEVICE(vkCmdCopyImageToBuffer);

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
    const uint32_t *pixels = NULL;
    static uint32_t copy[SIDE * SIDE];
    if (frame) {
        VkPhysicalDeviceMemoryProperties mem;
        vkGetPhysicalDeviceMemoryProperties(phys, &mem);
        VkImageCreateInfo ii = {.sType = VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO,
                                .imageType = VK_IMAGE_TYPE_2D,
                                .format = VK_FORMAT_B8G8R8A8_UNORM,
                                .extent = {SIDE, SIDE, 1},
                                .mipLevels = 1,
                                .arrayLayers = 1,
                                .samples = VK_SAMPLE_COUNT_1_BIT,
                                .tiling = VK_IMAGE_TILING_OPTIMAL,
                                .usage = VK_IMAGE_USAGE_TRANSFER_DST_BIT |
                                         VK_IMAGE_USAGE_TRANSFER_SRC_BIT |
                                         VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT};
        VkImage image;
        check(vkCreateImage(dev, &ii, NULL, &image), "vkCreateImage");
        VkBufferCreateInfo bci = {.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO,
                                  .size = sizeof copy,
                                  .usage = VK_BUFFER_USAGE_TRANSFER_DST_BIT};
        VkBuffer buffer;
        check(vkCreateBuffer(dev, &bci, NULL, &buffer), "vkCreateBuffer");
        /* The image in the device's memory, the buffer in memory the host
         * sees as the device writes it. */
        VkMemoryRequirements ireq, breq;
        vkGetImageMemoryRequirements(dev, image, &ireq);
        vkGetBufferMemoryRequirements(dev, buffer, &breq);
        VkMemoryPropertyFlags host = VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT |
                                     VK_MEMORY_PROPERTY_HOST_COHERENT_BIT;
        uint32_t itype = mem.memoryTypeCount, btype = mem.memoryTypeCount;
        for (uint32_t t = mem.memoryTypeCount; t-- > 0;) {
            VkMemoryPropertyFlags f = mem.memoryTypes[t].propertyFlags;
            if ((ireq.memoryTypeBits >> t & 1) && (f & VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT))
                itype = t;
            if ((breq.memoryTypeBits >> t & 1) && (f & host) == host) btype = t;
        }
        if (itype == mem.memoryTypeCount || btype == mem.memoryTypeCount) {
            fprintf(stderr, "vkbench: no memory for the frame\n");
            return 1;
        }
        VkMemoryAllocateInfo ia = {.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,
                                   .allocationSize = ireq.size,
                                   .memoryTypeIndex = itype};
        VkMemoryAllocateInfo ba = {.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,
                                   .allocationSize = breq.size,
                                   .memoryTypeIndex = btype};
        VkDeviceMemory imem, bmem;
        check(vkAllocateMemory(dev, &ia, NULL, &imem), "vkAllocateMemory");
        check(vkAllocateMemory(dev, &ba, NULL, &bmem), "vkAllocateMemory");
        check(vkBindImageMemory(dev, image, imem, 0), "vkBindImageMemory");
        check(vkBindBufferMemory(dev, buffer, bmem, 0), "vkBindBufferMemory");
        void *mapped;
        check(vkMapMemory(dev, bmem, 0, VK_WHOLE_SIZE, 0, &mapped), "vkMapMemory");
        pixels = mapped;

        VkImageSubresourceRange whole = {VK_IMAGE_ASPECT_COLOR_BIT, 0, 1, 0, 1};
        VkImageMemoryBarrier to_clear = {.sType = VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER,
                                         .dstAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT,
                                         .oldLayout = VK_IMAGE_LAYOUT_UNDEFINED,
                                         .newLayout = VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL,
                                         .srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
                                         .dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
                                         .image = image,
                                         .subresourceRange = whole};
        vkCmdPipelineBarrier(cmd, VK_PIPELINE_STAGE_TOP_OF_PIPE_BIT,
                             VK_PIPELINE_STAGE_TRANSFER_BIT, 0, 0, NULL, 0, NULL, 1, &to_clear);
        /* Blue, opaque: 0xff0000ff as B8G8R8A8 read as a word. */
        VkClearColorValue blue = {.float32 = {0, 0, 1, 1}};
        vkCmdClearColorImage(cmd, image, VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL, &blue, 1, &whole);
        VkImageMemoryBarrier to_copy = to_clear;
        to_copy.srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT;
        to_copy.dstAccessMask = VK_ACCESS_TRANSFER_READ_BIT;
        to_copy.oldLayout = VK_IMAGE_LAYOUT_TRANSFER_DST_OPTIMAL;
        to_copy.newLayout = VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL;
        vkCmdPipelineBarrier(cmd, VK_PIPELINE_STAGE_TRANSFER_BIT,
                             VK_PIPELINE_STAGE_TRANSFER_BIT, 0, 0, NULL, 0, NULL, 1, &to_copy);
        VkBufferImageCopy region = {.imageSubresource = {VK_IMAGE_ASPECT_COLOR_BIT, 0, 0, 1},
                                    .imageExtent = {SIDE, SIDE, 1}};
        vkCmdCopyImageToBuffer(cmd, image, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL, buffer, 1,
                               &region);
        VkBufferMemoryBarrier to_host = {.sType = VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER,
                                         .srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT,
                                         .dstAccessMask = VK_ACCESS_HOST_READ_BIT,
                                         .srcQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
                                         .dstQueueFamilyIndex = VK_QUEUE_FAMILY_IGNORED,
                                         .buffer = buffer,
                                         .size = VK_WHOLE_SIZE};
        vkCmdPipelineBarrier(cmd, VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_HOST_BIT, 0,
                             0, NULL, 1, &to_host, 0, NULL);
    }
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
        if (frame) {
            memcpy(copy, pixels, sizeof copy);
            if (copy[0] != 0xff0000ffu) {
                fprintf(stderr, "vkbench: the frame's first pixel is %08x\n", copy[0]);
                return 1;
            }
        }
    }
    printf("%s (us): %.2f\n", frame ? "frame" : "submission round trip",
           (now() - start) * 1e6 / n);
    return 0;
}
