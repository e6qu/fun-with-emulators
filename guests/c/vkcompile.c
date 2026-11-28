/* A compute pipeline Metal has never compiled: its shader's entry point is
 * named `k` and the 10 digits given (a name new to each run), so the Mac's
 * driver compiles it anew, through Metal's shader compiler, which works
 * only in a process exec'd since its fork. It makes an instance, a device,
 * the shader module and the pipeline through fwe's driver, printing each
 * command's result.
 *
 * Built freestanding against musl's shared library, run in an Alpine root
 * with its loader. */
int printf(const char *fmt, ...);
void *dlopen(const char *path, int flags);
void *dlsym(void *lib, const char *name);
char *dlerror(void);
unsigned long strlen(const char *s);
void *memcpy(void *d, const void *s, unsigned long n);

#define RTLD_NOW 2

typedef void (*vk_fn)(void);
typedef vk_fn (*gipa_t)(void *instance, const char *name);

/* The shader, as `spirv-as --target-env vulkan1.0` assembles it:
 *
 *                OpCapability Shader
 *                OpMemoryModel Logical GLSL450
 *                OpEntryPoint GLCompute %main "k0000000000"
 *                OpExecutionMode %main LocalSize 1 1 1
 *        %void = OpTypeVoid
 *          %fn = OpTypeFunction %void
 *        %main = OpFunction %void None %fn
 *       %entry = OpLabel
 *                OpReturn
 *                OpFunctionEnd
 */
static const unsigned SHADER[] = {
    0x07230203, 0x00010000, 0x00070000, 0x00000005, 0x00000000, 0x00020011,
    0x00000001, 0x0003000e, 0x00000000, 0x00000001, 0x0006000f, 0x00000005,
    0x00000001, 0x3030306b, 0x30303030, 0x00303030, 0x00060010, 0x00000001,
    0x00000011, 0x00000001, 0x00000001, 0x00000001, 0x00020013, 0x00000002,
    0x00030021, 0x00000003, 0x00000002, 0x00050036, 0x00000002, 0x00000001,
    0x00000000, 0x00000003, 0x000200f8, 0x00000004, 0x000100fd, 0x00010038,
};
/* Where the entry point's name, "k" and 10 digits, is in it (bytes). */
#define NAME_AT 52
#define DIGITS 10

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
struct module_info {
    int type;
    const void *next;
    unsigned flags;
    unsigned long size;
    const unsigned *code;
};
struct layout_info {
    int type;
    const void *next;
    unsigned flags, set_layouts;
    const void *set_layout_list;
    unsigned ranges;
    const void *range_list;
};
struct stage_info {
    int type;
    const void *next;
    unsigned flags, stage;
    unsigned long module;
    const char *name;
    const void *specialization;
};
struct pipeline_info {
    int type;
    const void *next;
    unsigned flags;
    struct stage_info stage;
    unsigned long layout, base;
    int base_index;
};

int main(int argc, char **argv) {
    if (argc != 2 || strlen(argv[1]) != DIGITS) {
        printf("usage: vkcompile DIGITS (%d of them)\n", DIGITS);
        return 2;
    }
    char name[DIGITS + 2] = "k";
    memcpy(name + 1, argv[1], DIGITS + 1);
    unsigned code[sizeof SHADER / sizeof SHADER[0]];
    memcpy(code, SHADER, sizeof SHADER);
    memcpy((char *)code + NAME_AT, name, DIGITS + 1);

    void *lib = dlopen("libvulkan.so.1", RTLD_NOW);
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

    int (*create_module)(void *, const struct module_info *, const void *, unsigned long *) =
        (int (*)(void *, const struct module_info *, const void *, unsigned long *))gipa(
            instance, "vkCreateShaderModule");
    struct module_info mi = {16, 0, 0, sizeof code, code};
    unsigned long module = 0;
    printf("shader module: %d\n", create_module(device, &mi, 0, &module));
    int (*create_layout)(void *, const struct layout_info *, const void *, unsigned long *) =
        (int (*)(void *, const struct layout_info *, const void *, unsigned long *))gipa(
            instance, "vkCreatePipelineLayout");
    struct layout_info li = {30, 0, 0, 0, 0, 0, 0};
    unsigned long layout = 0;
    printf("pipeline layout: %d\n", create_layout(device, &li, 0, &layout));
    int (*create_pipelines)(void *, unsigned long, unsigned, const struct pipeline_info *,
                            const void *, unsigned long *) =
        (int (*)(void *, unsigned long, unsigned, const struct pipeline_info *, const void *,
                 unsigned long *))gipa(instance, "vkCreateComputePipelines");
    struct pipeline_info pi = {29, 0, 0, {18, 0, 0, 0x20, module, name, 0}, layout, 0, -1};
    unsigned long pipeline = 0;
    r = create_pipelines(device, 0, 1, &pi, 0, &pipeline);
    printf("compute pipeline: %d\n", r);
    void (*destroy_device)(void *, const void *) =
        (void (*)(void *, const void *))gipa(instance, "vkDestroyDevice");
    destroy_device(device, 0);
    return r == 0 ? 0 : 1;
}
