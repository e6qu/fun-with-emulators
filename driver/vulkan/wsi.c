/* fwe's Linux Vulkan driver: the window systems (X11, through xcb or Xlib).
 *
 * A program's surface is the loader's, of an X window (VkIcdSurfaceXcb or
 * VkIcdSurfaceXlib). Its swapchain is the Mac driver's, made on a surface
 * of no window (VK_EXT_headless_surface), so acquiring an image, and the
 * fences and semaphores of it, are the driver's own; the swapchain's handle
 * is the driver's, and every command of it but present and its end is the
 * driver's. The surface's queries ask the driver of a surface of no window,
 * and the X server of the window's size.
 *
 * Present copies the image to memory the process reads, on the queue the
 * program presents on (after the semaphores it gave), waits for the copy,
 * puts the pixels in the window (xcb_put_image), and presents the image to
 * the driver's swapchain, which makes it acquirable again. The window's
 * size, asked of the X server after each frame, paces frames to what the
 * server takes, and says when the window has a size other than the
 * swapchain's (VK_SUBOPTIMAL_KHR).
 *
 * xcb and Xlib are the program's: the library finds them with dlopen. */
#include "fwe_vk.h"

/* The C library's, where the process has them (glibc 2.34 on, musl). */
extern void *dlopen(const char *, int) __attribute__((weak, visibility("default")));
extern void *dlsym(void *, const char *) __attribute__((weak, visibility("default")));
#define RTLD_NOW 2

#define SYS_sched_yield 124

/* Vulkan's values used here. */
#define VK_SUCCESS 0
#define VK_INCOMPLETE 5
#define VK_SUBOPTIMAL_KHR 1000001003
#define VK_ERROR_OUT_OF_HOST_MEMORY (-1)
#define VK_ERROR_INITIALIZATION_FAILED (-3)
#define VK_ERROR_FORMAT_NOT_SUPPORTED (-11)
#define VK_ERROR_SURFACE_LOST_KHR (-1000000000)
#define VK_ERROR_OUT_OF_DATE_KHR (-1000001004)

#define VK_STRUCTURE_TYPE_SUBMIT_INFO 4
#define VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO 5
#define VK_STRUCTURE_TYPE_MAPPED_MEMORY_RANGE 6
#define VK_STRUCTURE_TYPE_FENCE_CREATE_INFO 8
#define VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO 12
#define VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO 39
#define VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO 40
#define VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO 42
#define VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER 44
#define VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER 45
#define VK_STRUCTURE_TYPE_PRESENT_INFO_KHR 1000001001
#define VK_STRUCTURE_TYPE_HEADLESS_SURFACE_CREATE_INFO_EXT 1000256000

#define VK_FORMAT_B8G8R8A8_UNORM 44
#define VK_FORMAT_B8G8R8A8_SRGB 50
#define VK_COLOR_SPACE_SRGB_NONLINEAR_KHR 0
#define VK_PRESENT_MODE_FIFO_RELAXED_KHR 3
#define VK_IMAGE_USAGE_TRANSFER_SRC_BIT 0x1
#define VK_BUFFER_USAGE_TRANSFER_DST_BIT 0x2
#define VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT 0x2
#define VK_MEMORY_PROPERTY_HOST_COHERENT_BIT 0x4
#define VK_MEMORY_PROPERTY_HOST_CACHED_BIT 0x8
#define VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT 0x2
#define VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL 6
#define VK_IMAGE_LAYOUT_PRESENT_SRC_KHR 1000001002
#define VK_ACCESS_TRANSFER_READ_BIT 0x800
#define VK_ACCESS_TRANSFER_WRITE_BIT 0x1000
#define VK_ACCESS_HOST_READ_BIT 0x2000
#define VK_PIPELINE_STAGE_TRANSFER_BIT 0x1000
#define VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT 0x2000
#define VK_PIPELINE_STAGE_HOST_BIT 0x4000
#define VK_PIPELINE_STAGE_ALL_COMMANDS_BIT 0x10000
#define VK_IMAGE_ASPECT_COLOR_BIT 0x1
#define VK_QUEUE_FAMILY_IGNORED (~0u)
#define VK_DEVICE_GROUP_PRESENT_MODE_LOCAL_BIT_KHR 0x1

#define VK_ICD_WSI_PLATFORM_XCB 3
#define VK_ICD_WSI_PLATFORM_XLIB 4

/* Vulkan's structures used here, as its headers lay them out. */
struct extent {
    uint32_t width, height;
};

struct surface_capabilities {
    uint32_t min_image_count, max_image_count;
    struct extent current_extent, min_image_extent, max_image_extent;
    uint32_t max_image_array_layers, supported_transforms, current_transform;
    uint32_t supported_composite_alpha, supported_usage_flags;
};
_Static_assert(sizeof(struct surface_capabilities) == 52, "VkSurfaceCapabilitiesKHR");

struct surface_format {
    uint32_t format, color_space;
};

struct surface_capabilities2 {
    uint32_t s_type;
    void *next;
    struct surface_capabilities caps;
};
_Static_assert(sizeof(struct surface_capabilities2) == 72, "VkSurfaceCapabilities2KHR");

struct surface_format2 {
    uint32_t s_type;
    void *next;
    struct surface_format format;
};
_Static_assert(sizeof(struct surface_format2) == 24, "VkSurfaceFormat2KHR");

struct surface_info2 {
    uint32_t s_type;
    const void *next;
    uint64_t surface;
};

struct headless_info {
    uint32_t s_type;
    const void *next;
    uint32_t flags;
};

struct swapchain_info {
    uint32_t s_type;
    const void *next;
    uint32_t flags;
    uint64_t surface;
    uint32_t min_image_count, image_format, image_color_space;
    struct extent image_extent;
    uint32_t image_array_layers, image_usage, image_sharing_mode;
    uint32_t queue_family_index_count;
    const uint32_t *queue_family_indices;
    uint32_t pre_transform, composite_alpha, present_mode, clipped;
    uint64_t old_swapchain;
};
_Static_assert(sizeof(struct swapchain_info) == 104, "VkSwapchainCreateInfoKHR");
_Static_assert(__builtin_offsetof(struct swapchain_info, surface) == 24, "surface");
_Static_assert(__builtin_offsetof(struct swapchain_info, image_extent) == 44, "imageExtent");
_Static_assert(__builtin_offsetof(struct swapchain_info, image_usage) == 56, "imageUsage");

struct present_info {
    uint32_t s_type;
    const void *next;
    uint32_t wait_count;
    const uint64_t *waits;
    uint32_t swapchain_count;
    const uint64_t *swapchains;
    const uint32_t *image_indices;
    int32_t *results;
};
_Static_assert(sizeof(struct present_info) == 64, "VkPresentInfoKHR");

struct submit_info {
    uint32_t s_type;
    const void *next;
    uint32_t wait_count;
    const uint64_t *waits;
    const uint32_t *wait_stages;
    uint32_t command_buffer_count;
    void *const *command_buffers;
    uint32_t signal_count;
    const uint64_t *signals;
};
_Static_assert(sizeof(struct submit_info) == 72, "VkSubmitInfo");

struct memory_properties {
    uint32_t type_count;
    struct {
        uint32_t flags, heap;
    } types[32];
    uint32_t heap_count;
    struct {
        uint64_t size;
        uint32_t flags;
    } heaps[16];
};
_Static_assert(sizeof(struct memory_properties) == 520, "VkPhysicalDeviceMemoryProperties");

struct memory_requirements {
    uint64_t size, alignment;
    uint32_t type_bits;
};

struct buffer_info {
    uint32_t s_type;
    const void *next;
    uint32_t flags;
    uint64_t size;
    uint32_t usage, sharing_mode, queue_family_index_count;
    const uint32_t *queue_family_indices;
};

struct allocate_info {
    uint32_t s_type;
    const void *next;
    uint64_t size;
    uint32_t type;
};

struct mapped_range {
    uint32_t s_type;
    const void *next;
    uint64_t memory, offset, size;
};

struct pool_info {
    uint32_t s_type;
    const void *next;
    uint32_t flags, family;
};

struct command_buffers_info {
    uint32_t s_type;
    const void *next;
    uint64_t pool;
    uint32_t level, count;
};

struct begin_info {
    uint32_t s_type;
    const void *next;
    uint32_t flags;
    const void *inheritance;
};

struct fence_info {
    uint32_t s_type;
    const void *next;
    uint32_t flags;
};

struct subresource_range {
    uint32_t aspect, base_level, levels, base_layer, layers;
};

struct image_barrier {
    uint32_t s_type;
    const void *next;
    uint32_t src_access, dst_access, old_layout, new_layout, src_family, dst_family;
    uint64_t image;
    struct subresource_range range;
};
_Static_assert(sizeof(struct image_barrier) == 72, "VkImageMemoryBarrier");

struct buffer_barrier {
    uint32_t s_type;
    const void *next;
    uint32_t src_access, dst_access, src_family, dst_family;
    uint64_t buffer, offset, size;
};
_Static_assert(sizeof(struct buffer_barrier) == 56, "VkBufferMemoryBarrier");

struct buffer_image_copy {
    uint64_t buffer_offset;
    uint32_t row_length, image_height;
    struct {
        uint32_t aspect, level, base_layer, layers;
    } subresource;
    int32_t offset[3];
    uint32_t extent[3];
};
_Static_assert(sizeof(struct buffer_image_copy) == 56, "VkBufferImageCopy");

struct rect2d {
    int32_t x, y;
    struct extent extent;
};

/* The loader's surfaces of X windows (vk_icd.h). */
struct icd_surface_xcb {
    uint32_t platform;
    void *connection;
    uint32_t window;
};

struct icd_surface_xlib {
    uint32_t platform;
    void *display;
    unsigned long window;
};

/* xcb's and Xlib's functions, the program's own. */
typedef struct {
    unsigned int sequence;
} xcb_cookie;

struct xcb_geometry_reply {
    uint8_t response_type, depth;
    uint16_t sequence;
    uint32_t length, root;
    int16_t x, y;
    uint16_t width, height, border_width;
    uint8_t pad[2];
};

static struct {
    xcb_cookie (*get_geometry)(void *c, uint32_t drawable);
    struct xcb_geometry_reply *(*get_geometry_reply)(void *c, xcb_cookie cookie, void **error);
    uint32_t (*generate_id)(void *c);
    xcb_cookie (*create_gc)(void *c, uint32_t gc, uint32_t drawable, uint32_t mask, const void *values);
    xcb_cookie (*free_gc)(void *c, uint32_t gc);
    xcb_cookie (*put_image)(void *c, uint8_t format, uint32_t drawable, uint32_t gc, uint16_t width,
                            uint16_t height, int16_t x, int16_t y, uint8_t left_pad, uint8_t depth,
                            uint32_t length, const uint8_t *data);
    int (*flush)(void *c);
    uint32_t (*maximum_request_length)(void *c);
    int (*connection_has_error)(void *c);
    void (*free)(void *p);
    void *(*xlib_connection)(void *display); /* XGetXCBConnection */
} xcb;

/* 0: not looked for; 1: being looked for; 2: found; 3: not there. */
static int xcb_state;

static int load_xcb(void) {
    for (;;) {
        int s = __atomic_load_n(&xcb_state, __ATOMIC_ACQUIRE);
        if (s >= 2) return s == 2;
        int none = 0;
        if (s == 0 && __atomic_compare_exchange_n(&xcb_state, &none, 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            break;
        fwe_syscall(SYS_sched_yield, 0, 0, 0, 0, 0, 0);
    }
    int found = 0;
    void *lib = dlopen ? dlopen("libxcb.so.1", RTLD_NOW) : 0;
    if (lib && dlsym) {
#define FIND(field, name) *(void **)&xcb.field = dlsym(lib, name)
        FIND(get_geometry, "xcb_get_geometry");
        FIND(get_geometry_reply, "xcb_get_geometry_reply");
        FIND(generate_id, "xcb_generate_id");
        FIND(create_gc, "xcb_create_gc");
        FIND(free_gc, "xcb_free_gc");
        FIND(put_image, "xcb_put_image");
        FIND(flush, "xcb_flush");
        FIND(maximum_request_length, "xcb_get_maximum_request_length");
        FIND(connection_has_error, "xcb_connection_has_error");
        FIND(free, "free");
        found = xcb.get_geometry && xcb.get_geometry_reply && xcb.generate_id && xcb.create_gc &&
                xcb.free_gc && xcb.put_image && xcb.flush && xcb.maximum_request_length &&
                xcb.connection_has_error && xcb.free;
        /* Xlib's way to its connection, where the program has Xlib. */
        void *x11 = dlopen("libX11-xcb.so.1", RTLD_NOW);
        if (x11) FIND(xlib_connection, "XGetXCBConnection");
#undef FIND
    }
    __atomic_store_n(&xcb_state, found ? 2 : 3, __ATOMIC_RELEASE);
    return found;
}

/* The X window a surface is of. */
struct window {
    void *connection;
    uint32_t id;
};

static int window_of(uint64_t surface, struct window *w) {
    const uint32_t *platform = (const uint32_t *)(uintptr_t)surface;
    if (!platform || !load_xcb()) return 0;
    if (*platform == VK_ICD_WSI_PLATFORM_XCB) {
        const struct icd_surface_xcb *s = (const void *)platform;
        w->connection = s->connection;
        w->id = s->window;
        return w->connection != 0;
    }
    if (*platform == VK_ICD_WSI_PLATFORM_XLIB && xcb.xlib_connection) {
        const struct icd_surface_xlib *s = (const void *)platform;
        w->connection = xcb.xlib_connection(s->display);
        w->id = (uint32_t)s->window;
        return w->connection != 0;
    }
    return 0;
}

/* The window's size and depth, from the X server. */
struct geometry {
    uint32_t width, height, depth;
};

static int geometry_of(const struct window *w, struct geometry *g) {
    if (xcb.connection_has_error(w->connection)) return 0;
    void *error = 0;
    struct xcb_geometry_reply *r =
        xcb.get_geometry_reply(w->connection, xcb.get_geometry(w->connection, w->id), &error);
    if (error) xcb.free(error);
    if (!r) return 0;
    g->width = r->width;
    g->height = r->height;
    g->depth = r->depth;
    xcb.free(r);
    return 1;
}

/* Depths whose pixels are 32 bits, as B8G8R8A8 images' are. */
static int depth_shown(uint32_t depth) { return depth == 24 || depth == 32; }

/* A surface of no window, on the instance of physical device `pd`, for the
 * driver to answer a surface's queries: 0 if it could not be made. */
static uint64_t headless(void *pd, void **instance) {
    *instance = fwe_vk_parent(pd);
    struct headless_info info = {VK_STRUCTURE_TYPE_HEADLESS_SURFACE_CREATE_INFO_EXT, 0, 0};
    uint64_t surface = 0;
    if (!*instance || fwe_host_vkCreateHeadlessSurfaceEXT(*instance, &info, 0, &surface) != VK_SUCCESS)
        return 0;
    return surface;
}

/* Write `n` items of `size` bytes from `items` to an enumeration's
 * `count` and `out`, as Vulkan's enumerations do. */
static int32_t enumerate(uint32_t *count, void *out, const void *items, uint32_t n, size_t size) {
    if (!out) {
        *count = n;
        return VK_SUCCESS;
    }
    uint32_t given = *count < n ? *count : n;
    memcpy(out, items, given * size);
    *count = given;
    return given < n ? VK_INCOMPLETE : VK_SUCCESS;
}

void fwe_wsi_vkDestroySurfaceKHR(void *instance, uint64_t surface, void *allocator) {
    /* The loader's own, which it frees. */
    (void)instance, (void)surface, (void)allocator;
}

int32_t fwe_wsi_vkGetPhysicalDeviceSurfaceSupportKHR(void *pd, uint32_t family, uint64_t surface, void *supported) {
    (void)pd, (void)family;
    struct window w;
    struct geometry g;
    *(uint32_t *)supported = window_of(surface, &w) && geometry_of(&w, &g) && depth_shown(g.depth);
    return VK_SUCCESS;
}

static int32_t capabilities(void *pd, uint64_t surface, struct surface_capabilities *caps) {
    struct window w;
    struct geometry g;
    if (!window_of(surface, &w) || !geometry_of(&w, &g)) return VK_ERROR_SURFACE_LOST_KHR;
    void *instance;
    uint64_t h = headless(pd, &instance);
    if (!h) return VK_ERROR_INITIALIZATION_FAILED;
    int32_t r = fwe_host_vkGetPhysicalDeviceSurfaceCapabilitiesKHR(pd, h, caps);
    fwe_host_vkDestroySurfaceKHR(instance, h, 0);
    if (r != VK_SUCCESS) return r;
    /* An X window's images are its size, as Linux's drivers have them. */
    struct extent e = {g.width, g.height};
    caps->current_extent = caps->min_image_extent = caps->max_image_extent = e;
    return VK_SUCCESS;
}

int32_t fwe_wsi_vkGetPhysicalDeviceSurfaceCapabilitiesKHR(void *pd, uint64_t surface, void *caps) {
    return capabilities(pd, surface, caps);
}

int32_t fwe_wsi_vkGetPhysicalDeviceSurfaceCapabilities2KHR(void *pd, void *info, void *caps) {
    const struct surface_info2 *i = info;
    return capabilities(pd, i->surface, &((struct surface_capabilities2 *)caps)->caps);
}

/* The formats the window shows (32-bit pixels, blue first: X's) that the
 * driver's swapchains have: up to 2. */
static int32_t formats(void *pd, uint64_t surface, struct surface_format *out, uint32_t *n) {
    struct window w;
    if (!window_of(surface, &w)) return VK_ERROR_SURFACE_LOST_KHR;
    void *instance;
    uint64_t h = headless(pd, &instance);
    if (!h) return VK_ERROR_INITIALIZATION_FAILED;
    struct surface_format host[64];
    uint32_t count = 64;
    int32_t r = fwe_host_vkGetPhysicalDeviceSurfaceFormatsKHR(pd, h, &count, host);
    fwe_host_vkDestroySurfaceKHR(instance, h, 0);
    if (r < 0) return r;
    *n = 0;
    for (uint32_t i = 0; i < count; i++) {
        int shown = host[i].format == VK_FORMAT_B8G8R8A8_UNORM || host[i].format == VK_FORMAT_B8G8R8A8_SRGB;
        if (shown && host[i].color_space == VK_COLOR_SPACE_SRGB_NONLINEAR_KHR && *n < 2) out[(*n)++] = host[i];
    }
    return VK_SUCCESS;
}

int32_t fwe_wsi_vkGetPhysicalDeviceSurfaceFormatsKHR(void *pd, uint64_t surface, void *count, void *out) {
    struct surface_format list[2];
    uint32_t n;
    int32_t r = formats(pd, surface, list, &n);
    return r != VK_SUCCESS ? r : enumerate(count, out, list, n, sizeof list[0]);
}

int32_t fwe_wsi_vkGetPhysicalDeviceSurfaceFormats2KHR(void *pd, void *info, void *count, void *out) {
    struct surface_format list[2];
    uint32_t n;
    int32_t r = formats(pd, ((const struct surface_info2 *)info)->surface, list, &n);
    if (r != VK_SUCCESS) return r;
    if (!out) return enumerate(count, 0, 0, n, 0);
    uint32_t *c = count, given = *c < n ? *c : n;
    for (uint32_t i = 0; i < given; i++) ((struct surface_format2 *)out)[i].format = list[i];
    *c = given;
    return given < n ? VK_INCOMPLETE : VK_SUCCESS;
}

int32_t fwe_wsi_vkGetPhysicalDeviceSurfacePresentModesKHR(void *pd, uint64_t surface, void *count, void *out) {
    struct window w;
    if (!window_of(surface, &w)) return VK_ERROR_SURFACE_LOST_KHR;
    void *instance;
    uint64_t h = headless(pd, &instance);
    if (!h) return VK_ERROR_INITIALIZATION_FAILED;
    uint32_t host[16], n = 16, modes[16], given = 0;
    int32_t r = fwe_host_vkGetPhysicalDeviceSurfacePresentModesKHR(pd, h, &n, host);
    fwe_host_vkDestroySurfaceKHR(instance, h, 0);
    if (r < 0) return r;
    /* Immediate, mailbox, FIFO and relaxed FIFO: those of a window. */
    for (uint32_t i = 0; i < n; i++)
        if (host[i] <= VK_PRESENT_MODE_FIFO_RELAXED_KHR) modes[given++] = host[i];
    return enumerate(count, out, modes, given, sizeof modes[0]);
}

int32_t fwe_wsi_vkGetDeviceGroupSurfacePresentModesKHR(void *device, uint64_t surface, void *modes) {
    (void)device, (void)surface;
    *(uint32_t *)modes = VK_DEVICE_GROUP_PRESENT_MODE_LOCAL_BIT_KHR;
    return VK_SUCCESS;
}

int32_t fwe_wsi_vkGetPhysicalDevicePresentRectanglesKHR(void *pd, uint64_t surface, void *count, void *out) {
    (void)pd;
    struct window w;
    struct geometry g;
    if (!window_of(surface, &w) || !geometry_of(&w, &g)) return VK_ERROR_SURFACE_LOST_KHR;
    struct rect2d whole = {0, 0, {g.width, g.height}};
    return enumerate(count, out, &whole, 1, sizeof whole);
}

/* A swapchain's own: the window it shows in, the memory its frames are
 * read to, and the commands that copy each image there. */
struct chain {
    struct chain *next;
    size_t size; /* of this allocation */
    uint64_t swapchain;
    void *device, *instance;
    uint64_t surface; /* of no window, the swapchain's */
    struct window window;
    uint32_t gc, depth;
    struct extent extent;
    /* The frame's memory, mapped. */
    uint64_t buffer, memory;
    uint8_t *pixels;
    int coherent;
    uint64_t fence;
    /* The copies, made for the family of the queue presenting. */
    uint64_t pool;
    uint32_t family;
    uint32_t image_count;
    uint64_t *images;
    void **copies;
};

static struct chain *chains;
static int chains_lock;

static void lock(void) {
    while (__atomic_exchange_n(&chains_lock, 1, __ATOMIC_ACQUIRE))
        fwe_syscall(SYS_sched_yield, 0, 0, 0, 0, 0, 0);
}

static void unlock(void) { __atomic_store_n(&chains_lock, 0, __ATOMIC_RELEASE); }

static struct chain *find_chain(uint64_t swapchain, int take) {
    lock();
    struct chain **at = &chains;
    while (*at && (*at)->swapchain != swapchain) at = &(*at)->next;
    struct chain *c = *at;
    if (c && take) *at = c->next;
    unlock();
    return c;
}

/* A memory type of `bits` the process reads well: host-visible, coherent
 * and cached if there is one, then coherent, then any host-visible. */
static int read_memory_type(void *pd, uint32_t bits, int *coherent) {
    struct memory_properties props;
    fwe_host_vkGetPhysicalDeviceMemoryProperties(pd, &props);
    const uint32_t wants[3] = {
        VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT | VK_MEMORY_PROPERTY_HOST_CACHED_BIT,
        VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT,
        VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT,
    };
    for (int w = 0; w < 3; w++)
        for (uint32_t i = 0; i < props.type_count && i < 32; i++)
            if ((bits >> i & 1) && (props.types[i].flags & wants[w]) == wants[w]) {
                *coherent = (props.types[i].flags & VK_MEMORY_PROPERTY_HOST_COHERENT_BIT) != 0;
                return (int)i;
            }
    return -1;
}

static void destroy_chain(struct chain *c) {
    void *d = c->device;
    if (c->pool) fwe_host_vkDestroyCommandPool(d, c->pool, 0);
    if (c->fence) fwe_host_vkDestroyFence(d, c->fence, 0);
    if (c->pixels) fwe_host_vkUnmapMemory(d, c->memory);
    if (c->buffer) fwe_host_vkDestroyBuffer(d, c->buffer, 0);
    if (c->memory) fwe_host_vkFreeMemory(d, c->memory, 0);
    if (c->swapchain) fwe_host_vkDestroySwapchainKHR(d, c->swapchain, 0);
    if (c->surface) fwe_host_vkDestroySurfaceKHR(c->instance, c->surface, 0);
    if (c->gc) {
        xcb.free_gc(c->window.connection, c->gc);
        xcb.flush(c->window.connection);
    }
    fwe_free(c, c->size);
}

/* The memory a frame is read to, and the fence its copy signals. */
static int32_t frame_memory(struct chain *c, void *pd) {
    void *d = c->device;
    struct buffer_info bi = {VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO, 0, 0, (uint64_t)c->extent.width * c->extent.height * 4,
                             VK_BUFFER_USAGE_TRANSFER_DST_BIT, 0, 0, 0};
    int32_t r = fwe_host_vkCreateBuffer(d, &bi, 0, &c->buffer);
    if (r != VK_SUCCESS) return r;
    struct memory_requirements req;
    fwe_host_vkGetBufferMemoryRequirements(d, c->buffer, &req);
    int type = read_memory_type(pd, req.type_bits, &c->coherent);
    if (type < 0) return VK_ERROR_INITIALIZATION_FAILED;
    struct allocate_info ai = {VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO, 0, req.size, (uint32_t)type};
    if ((r = fwe_host_vkAllocateMemory(d, &ai, 0, &c->memory)) != VK_SUCCESS) return r;
    if ((r = fwe_host_vkBindBufferMemory(d, c->buffer, c->memory, 0)) != VK_SUCCESS) return r;
    void *at = 0;
    if ((r = fwe_host_vkMapMemory(d, c->memory, 0, ~0ull, 0, &at)) != VK_SUCCESS) return r;
    c->pixels = at;
    struct fence_info fi = {VK_STRUCTURE_TYPE_FENCE_CREATE_INFO, 0, 0};
    return fwe_host_vkCreateFence(d, &fi, 0, &c->fence);
}

int32_t fwe_wsi_vkCreateSwapchainKHR(void *device, void *info, void *allocator, void *out) {
    (void)allocator;
    const struct swapchain_info *given = info;
    struct window w;
    struct geometry g;
    if (!window_of(given->surface, &w) || !geometry_of(&w, &g)) return VK_ERROR_SURFACE_LOST_KHR;
    if (!depth_shown(g.depth)) return VK_ERROR_INITIALIZATION_FAILED;
    if (given->image_format != VK_FORMAT_B8G8R8A8_UNORM && given->image_format != VK_FORMAT_B8G8R8A8_SRGB)
        return VK_ERROR_FORMAT_NOT_SUPPORTED;
    void *pd = fwe_vk_parent(device);
    if (!pd) return VK_ERROR_INITIALIZATION_FAILED;
    void *instance;
    uint64_t surface = headless(pd, &instance);
    if (!surface) return VK_ERROR_INITIALIZATION_FAILED;
    /* On its own surface, so no swapchain of the driver's is retired by
     * it: the program's old one stays the program's to destroy. */
    struct swapchain_info host = *given;
    host.surface = surface;
    host.old_swapchain = 0;
    host.image_usage |= VK_IMAGE_USAGE_TRANSFER_SRC_BIT;
    uint64_t swapchain = 0;
    int32_t r = fwe_host_vkCreateSwapchainKHR(device, &host, 0, &swapchain);
    if (r != VK_SUCCESS) {
        fwe_host_vkDestroySurfaceKHR(instance, surface, 0);
        return r;
    }
    uint32_t n = 0;
    fwe_host_vkGetSwapchainImagesKHR(device, swapchain, &n, 0);
    size_t size = sizeof(struct chain) + n * (sizeof(uint64_t) + sizeof(void *));
    struct chain *c = fwe_alloc(size);
    if (!c) {
        fwe_host_vkDestroySwapchainKHR(device, swapchain, 0);
        fwe_host_vkDestroySurfaceKHR(instance, surface, 0);
        return VK_ERROR_OUT_OF_HOST_MEMORY;
    }
    c->size = size;
    c->swapchain = swapchain;
    c->device = device;
    c->instance = instance;
    c->surface = surface;
    c->window = w;
    c->depth = g.depth;
    c->extent = given->image_extent;
    c->image_count = n;
    c->images = (uint64_t *)(c + 1);
    c->copies = (void **)(c->images + n);
    r = fwe_host_vkGetSwapchainImagesKHR(device, swapchain, &c->image_count, c->images);
    if (r == VK_SUCCESS) r = frame_memory(c, pd);
    if (r != VK_SUCCESS) {
        destroy_chain(c);
        return r;
    }
    c->gc = xcb.generate_id(w.connection);
    xcb.create_gc(w.connection, c->gc, w.id, 0, 0);
    lock();
    c->next = chains;
    chains = c;
    unlock();
    *(uint64_t *)out = swapchain;
    return VK_SUCCESS;
}

void fwe_wsi_vkDestroySwapchainKHR(void *device, uint64_t swapchain, void *allocator) {
    (void)allocator;
    if (!swapchain) return;
    struct chain *c = find_chain(swapchain, 1);
    if (c)
        destroy_chain(c);
    else
        fwe_host_vkDestroySwapchainKHR(device, swapchain, 0);
}

/* Record the copy of image `i` to the frame's memory. */
static int32_t record(struct chain *c, uint32_t i) {
    void *cb = c->copies[i];
    struct begin_info bi = {VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO, 0, 0, 0};
    int32_t r = fwe_host_vkBeginCommandBuffer(cb, &bi);
    if (r != VK_SUCCESS) return r;
    struct subresource_range color = {VK_IMAGE_ASPECT_COLOR_BIT, 0, 1, 0, 1};
    struct image_barrier to_copy = {VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER, 0, 0, VK_ACCESS_TRANSFER_READ_BIT,
                                    VK_IMAGE_LAYOUT_PRESENT_SRC_KHR, VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL,
                                    VK_QUEUE_FAMILY_IGNORED, VK_QUEUE_FAMILY_IGNORED, c->images[i], color};
    fwe_host_vkCmdPipelineBarrier(cb, VK_PIPELINE_STAGE_ALL_COMMANDS_BIT, VK_PIPELINE_STAGE_TRANSFER_BIT, 0, 0, 0,
                                  0, 0, 1, &to_copy);
    struct buffer_image_copy region = {0, 0, 0, {VK_IMAGE_ASPECT_COLOR_BIT, 0, 0, 1}, {0, 0, 0},
                                       {c->extent.width, c->extent.height, 1}};
    fwe_host_vkCmdCopyImageToBuffer(cb, c->images[i], VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL, c->buffer, 1, &region);
    struct image_barrier back = {VK_STRUCTURE_TYPE_IMAGE_MEMORY_BARRIER, 0, VK_ACCESS_TRANSFER_READ_BIT, 0,
                                 VK_IMAGE_LAYOUT_TRANSFER_SRC_OPTIMAL, VK_IMAGE_LAYOUT_PRESENT_SRC_KHR,
                                 VK_QUEUE_FAMILY_IGNORED, VK_QUEUE_FAMILY_IGNORED, c->images[i], color};
    struct buffer_barrier to_host = {VK_STRUCTURE_TYPE_BUFFER_MEMORY_BARRIER, 0, VK_ACCESS_TRANSFER_WRITE_BIT,
                                     VK_ACCESS_HOST_READ_BIT, VK_QUEUE_FAMILY_IGNORED, VK_QUEUE_FAMILY_IGNORED,
                                     c->buffer, 0, ~0ull};
    fwe_host_vkCmdPipelineBarrier(cb, VK_PIPELINE_STAGE_TRANSFER_BIT,
                                  VK_PIPELINE_STAGE_BOTTOM_OF_PIPE_BIT | VK_PIPELINE_STAGE_HOST_BIT, 0, 0, 0, 1,
                                  &to_host, 1, &back);
    return fwe_host_vkEndCommandBuffer(cb);
}

/* The copies, for queues of `family`: made (and recorded) the first time
 * a queue of it presents. */
static int32_t copies_for(struct chain *c, uint32_t family) {
    if (c->pool && c->family == family) return VK_SUCCESS;
    if (c->pool) fwe_host_vkDestroyCommandPool(c->device, c->pool, 0);
    c->pool = 0;
    struct pool_info pi = {VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO, 0, 0, family};
    int32_t r = fwe_host_vkCreateCommandPool(c->device, &pi, 0, &c->pool);
    if (r != VK_SUCCESS) return r;
    c->family = family;
    struct command_buffers_info ai = {VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO, 0, c->pool, 0, c->image_count};
    if ((r = fwe_host_vkAllocateCommandBuffers(c->device, &ai, c->copies)) != VK_SUCCESS) return r;
    for (uint32_t i = 0; i < c->image_count; i++)
        if ((r = record(c, i)) != VK_SUCCESS) return r;
    return VK_SUCCESS;
}

/* Put the frame's pixels in the window, in requests the server takes. */
static void show(struct chain *c) {
    void *x = c->window.connection;
    uint32_t stride = c->extent.width * 4;
    uint64_t most = (uint64_t)xcb.maximum_request_length(x) * 4;
    uint32_t rows = most > 24 + stride ? (uint32_t)((most - 24) / stride) : 1;
    for (uint32_t y = 0; y < c->extent.height; y += rows) {
        uint32_t n = c->extent.height - y < rows ? c->extent.height - y : rows;
        xcb.put_image(x, 2 /* ZPixmap */, c->window.id, c->gc, (uint16_t)c->extent.width, (uint16_t)n, 0,
                      (int16_t)y, 0, (uint8_t)c->depth, n * stride, c->pixels + (uint64_t)y * stride);
    }
    xcb.flush(x);
}

/* Present image `index` of `c` on `queue`, after `waits` (its semaphores). */
static int32_t present_one(void *queue, struct chain *c, uint32_t index, const struct present_info *p, int waits) {
    if (index >= c->image_count) return VK_ERROR_OUT_OF_DATE_KHR;
    int32_t r = copies_for(c, fwe_vk_queue_family(queue));
    if (r != VK_SUCCESS) return r;
    uint32_t count = waits ? p->wait_count : 0;
    uint32_t stages[count ? count : 1];
    for (uint32_t i = 0; i < count; i++) stages[i] = VK_PIPELINE_STAGE_ALL_COMMANDS_BIT;
    struct submit_info si = {VK_STRUCTURE_TYPE_SUBMIT_INFO, 0, count, count ? p->waits : 0, stages, 1,
                             &c->copies[index], 0, 0};
    if ((r = fwe_host_vkQueueSubmit(queue, 1, &si, c->fence)) != VK_SUCCESS) return r;
    r = fwe_host_vkWaitForFences(c->device, 1, &c->fence, 1, ~0ull);
    fwe_host_vkResetFences(c->device, 1, &c->fence);
    if (r != VK_SUCCESS) return r;
    if (!c->coherent) {
        struct mapped_range range = {VK_STRUCTURE_TYPE_MAPPED_MEMORY_RANGE, 0, c->memory, 0, ~0ull};
        fwe_host_vkInvalidateMappedMemoryRanges(c->device, 1, &range);
    }
    show(c);
    /* The image back to the driver's swapchain, to be acquired again. */
    int32_t presented = VK_SUCCESS;
    struct present_info hp = {VK_STRUCTURE_TYPE_PRESENT_INFO_KHR, 0, 0, 0, 1, &c->swapchain, &index, &presented};
    r = fwe_host_vkQueuePresentKHR(queue, &hp);
    if (r < 0) return r;
    struct geometry g;
    if (!geometry_of(&c->window, &g)) return VK_ERROR_SURFACE_LOST_KHR;
    if (g.width != c->extent.width || g.height != c->extent.height) return VK_SUBOPTIMAL_KHR;
    return r;
}

int32_t fwe_wsi_vkQueuePresentKHR(void *queue, void *info) {
    const struct present_info *p = info;
    int32_t all = VK_SUCCESS;
    for (uint32_t i = 0; i < p->swapchain_count; i++) {
        struct chain *c = find_chain(p->swapchains[i], 0);
        int32_t r = c ? present_one(queue, c, p->image_indices[i], p, i == 0) : VK_ERROR_SURFACE_LOST_KHR;
        if (p->results) p->results[i] = r;
        if (r < 0 && all >= 0)
            all = r;
        else if (r == VK_SUBOPTIMAL_KHR && all == VK_SUCCESS)
            all = r;
    }
    return all;
}

/* Presentation support of an X connection's visual: the window systems'
 * queries of no surface. */
static uint32_t xcb_presentation_support(void *pd, uint32_t family, void *connection, uint32_t visual) {
    (void)pd, (void)family, (void)connection, (void)visual;
    return 1;
}

static uint32_t xlib_presentation_support(void *pd, uint32_t family, void *display, unsigned long visual) {
    (void)pd, (void)family, (void)display, (void)visual;
    return 1;
}

static int same(const char *a, const char *b) {
    while (*a && *a == *b) a++, b++;
    return *a == *b;
}

fwe_vk_fn fwe_wsi_proc(const char *name) {
    if (same(name, "vkGetPhysicalDeviceXcbPresentationSupportKHR")) return (fwe_vk_fn)xcb_presentation_support;
    if (same(name, "vkGetPhysicalDeviceXlibPresentationSupportKHR")) return (fwe_vk_fn)xlib_presentation_support;
    return 0;
}
