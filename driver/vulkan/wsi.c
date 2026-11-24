/* fwe's Linux Vulkan driver: the window systems (X11, through xcb and
 * Xlib-xcb), the library's own. */
#include "fwe_vk.h"

fwe_vk_fn fwe_wsi_proc(const char *name, enum fwe_vk_level level) {
    (void)name;
    (void)level;
    return 0;
}
