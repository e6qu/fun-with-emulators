/* fwe's Linux Vulkan driver, libvulkan_fwe.so: what its parts share.
 *
 * The library is freestanding: it makes its system calls itself (svc), and
 * needs nothing of the C library but dlopen and dlsym, for the window
 * systems' libraries, which it takes where the process has them (weak
 * references; without them there are no window systems). */

/* The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
 * "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
 * "OPTIONAL" in the Vulkan driver's comments are to be interpreted as
 * described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear
 * in all capitals, as shown here. */
#pragma once

#include <stddef.h>
#include <stdint.h>

#define FWE_VK_LIBRARY
#include "generated.h"

#define FWE_EXPORT __attribute__((visibility("default")))

/* VkResults the library gives. */
#define FWE_VK_SUCCESS 0
#define FWE_VK_INIT_FAILED (-3)            /* VK_ERROR_INITIALIZATION_FAILED */
#define FWE_VK_LOST (-4)                   /* VK_ERROR_DEVICE_LOST */
#define FWE_VK_INCOMPATIBLE_DRIVER (-9)    /* VK_ERROR_INCOMPATIBLE_DRIVER */

/* What a command's first argument is (crates/kernel/src/vulkan, Level). */
enum fwe_vk_level { FWE_VK_GLOBAL, FWE_VK_INSTANCE, FWE_VK_DEVICE };

/* Who answers a command for a program: the driver, through its stub; the
 * library's window systems (wsi.c); or no one (the library alone calls it,
 * through its stub). */
enum fwe_vk_use { FWE_VK_USE_STUB, FWE_VK_USE_WSI, FWE_VK_USE_INTERNAL };

/* The device's ioctl's record. */
struct fwe_vk_call {
    uint32_t command;
    uint32_t words;
    uint64_t args;
    uint64_t result;
};
_Static_assert(sizeof(struct fwe_vk_call) == FWE_VK_CALL_RECORD, "the call record");

typedef void (*fwe_vk_fn)(void);

/* A command the library has a stub for, by name. */
struct fwe_vk_entry {
    const char *name;
    fwe_vk_fn stub;
    enum fwe_vk_level level;
    enum fwe_vk_use use;
    uint32_t index; /* fwe's number for it */
};
extern const struct fwe_vk_entry fwe_vk_entries[];
extern const unsigned fwe_vk_entry_count;

/* Run command `command` with its `count` words `w`: its result, or
 * `failed` if the device could not run it. */
uint64_t fwe_vk_call(uint32_t command, const uint64_t *w, uint32_t count, uint64_t failed);

/* Whether object `handle` (NULL for none) has command `command`. */
int fwe_vk_has(const void *handle, uint32_t command);

/* The object `handle` is of (a physical device's instance, a device's
 * physical device), or NULL. */
void *fwe_vk_parent(const void *handle);

/* The family of queue `queue`. */
uint32_t fwe_vk_queue_family(const void *queue);

/* The window systems' functions the library answers by a name of no
 * command of the driver's (wsi.c): a physical device's (presentation
 * support), and an instance's (those and making surfaces of X windows). */
fwe_vk_fn fwe_wsi_physical_device_proc(const char *name);
fwe_vk_fn fwe_wsi_instance_proc(const char *name);

/* The library's own memory: `size` bytes, zeroed, or NULL. */
void *fwe_alloc(size_t size);
void fwe_free(void *p, size_t size);

void *memcpy(void *dst, const void *src, size_t n);
void *memset(void *dst, int c, size_t n);

/* A timeout in nanoseconds from now as an absolute CLOCK_MONOTONIC deadline
 * (UINT64_MAX stays forever). */
uint64_t fwe_vk_deadline(uint64_t timeout);

static inline uint64_t fwe_f32_bits(float f) {
    uint32_t u;
    __builtin_memcpy(&u, &f, sizeof u);
    return u;
}

static inline uint64_t fwe_f64_bits(double f) {
    uint64_t u;
    __builtin_memcpy(&u, &f, sizeof u);
    return u;
}

/* System calls. */
long fwe_syscall(long nr, long a, long b, long c, long d, long e, long f);
