#!/usr/bin/env python3
"""Generate fwe's Vulkan driver's calls from Vulkan's registry (vk.xml).

fwe's Linux Vulkan driver (driver/vulkan/) passes each Vulkan command a
Linux program makes to the Mac's Vulkan driver, in-process: the guest
library's stub for a command packs its arguments into an array of 64-bit
words and makes one ioctl on fwe's GPU device; fwe calls the Mac driver's
function for the command with them, typed, so the Mac's calling convention
is the compiler's to apply. This writes, from the registry:

  driver/vulkan/generated.h                 the device's interface
  driver/vulkan/generated.c                 the stubs and their names
  crates/kernel/src/vulkan/generated.rs     the calls, the commands' names,
                                            levels and outputs, the structs'
                                            sizes, and the extensions covered

Usage: python3 tools/gen-vulkan.py [path/to/vk.xml]
(default: Homebrew's vulkan-headers, $(brew --prefix)/share/vulkan/registry).
"""

import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_C = os.path.join(ROOT, "driver", "vulkan", "generated.c")
OUT_H = os.path.join(ROOT, "driver", "vulkan", "generated.h")
OUT_RS = os.path.join(ROOT, "crates", "kernel", "src", "vulkan", "generated.rs")

# Commands the guest library answers itself: finding functions. (The
# window systems' commands are its own too, by name: driver/vulkan/wsi.c.)
GUEST_SIDE = {
    "vkGetInstanceProcAddr",
    "vkGetDeviceProcAddr",
}

# The window systems' extensions the guest library builds its own on: a
# swapchain of the driver's, on a surface of no window (headless), whose
# images the library shows in the X window. Their commands are the host's
# (the library calls them), but the extensions are offered as the library's
# (crates/kernel/src/vulkan, GUEST_EXTENSIONS), not as the driver's.
HOST_WSI = {"VK_KHR_surface", "VK_KHR_swapchain", "VK_EXT_headless_surface"}

# Commands of the window systems the guest library answers itself
# (driver/vulkan/wsi.c, `fwe_wsi_<name>`): those that take a surface (the
# library's, of an X window), directly or in a structure, and present and a
# swapchain's end. Every other command of a swapchain's the driver answers:
# a guest's swapchain is the driver's.
WSI_ALSO = {"vkQueuePresentKHR", "vkDestroySwapchainKHR"}
# Extensions whose commands only the library calls: a surface of no window.
INTERNAL = {"VK_EXT_headless_surface"}


def holds_surface(reg, t, seen=()):
    """Whether type `t` is a surface or a structure that holds one."""
    t = reg.resolve(t)
    if t == "VkSurfaceKHR":
        return True
    ty = reg.types.get(t)
    if ty is None or ty.get("category") not in ("struct", "union") or t in seen:
        return False
    for m in ty.findall("member"):
        mt = m.find("type")
        if mt is not None and holds_surface(reg, mt.text, seen + (t,)):
            return True
    return False


def use_of(reg, name, exts):
    """Who answers command `name` for a program: the driver (its stub), the
    window systems of the library, or no one (the library's own)."""
    if any(name in exts[e]["commands"] for e in INTERNAL if e in exts):
        return "INTERNAL"
    if name in WSI_ALSO or any(holds_surface(reg, p["type"]) for p in reg.command(name)["params"]):
        return "WSI"
    return "STUB"


# Window systems' extensions: a block of another extension's that needs one
# brings commands and structures of window systems the library does not
# have (a device group's present modes, say): left out.
WSI_DEPENDS = ("VK_KHR_surface", "VK_KHR_swapchain", "VK_KHR_display")


def wsi_block(ext, req):
    """Whether block `req` of extension `ext` needs a window system's
    extension other than `ext`'s own kind."""
    return ext not in HOST_WSI and any(w in (req.get("depends") or "") for w in WSI_DEPENDS)


# Extensions never offered: their commands or structures hand the driver a
# function of the guest's to call (host code never calls guest code), or
# they speak of the Mac's own objects or of a host the guest is not on.
EXCLUDED_EXTENSIONS = {
    "VK_EXT_debug_utils",
    "VK_EXT_debug_report",
    "VK_EXT_device_memory_report",
    "VK_LUNARG_direct_driver_loading",
    "VK_EXT_debug_marker",
    "VK_KHR_portability_enumeration",
    # Window systems other than the library's own.
    "VK_KHR_display",
    "VK_KHR_display_swapchain",
    "VK_KHR_get_display_properties2",
    "VK_EXT_direct_mode_display",
    "VK_EXT_display_surface_counter",
    "VK_EXT_display_control",
    "VK_EXT_acquire_drm_display",
    "VK_KHR_surface_protected_capabilities",
    "VK_EXT_surface_maintenance1",
    "VK_KHR_surface_maintenance1",
    "VK_EXT_swapchain_maintenance1",
    "VK_KHR_swapchain_maintenance1",
    "VK_KHR_present_id",
    "VK_KHR_present_id2",
    "VK_KHR_present_wait",
    "VK_KHR_present_wait2",
    "VK_KHR_incremental_present",
    "VK_KHR_shared_presentable_image",
    "VK_EXT_swapchain_colorspace",
    "VK_EXT_hdr_metadata",
    "VK_GOOGLE_display_timing",
    "VK_EXT_present_timing",
    "VK_EXT_full_screen_exclusive",
    "VK_AMD_display_native_hdr",
    "VK_NV_present_barrier",
    "VK_NV_low_latency2",
    "VK_KHR_present_mode_fifo_latest_ready",
    "VK_EXT_present_mode_fifo_latest_ready",
    # External objects of other systems (descriptors, Metal objects).
    "VK_KHR_external_memory_fd",
    "VK_KHR_external_semaphore_fd",
    "VK_KHR_external_fence_fd",
    "VK_EXT_external_memory_dma_buf",
    "VK_EXT_image_drm_format_modifier",
    "VK_EXT_external_memory_host",
    "VK_EXT_metal_objects",
    "VK_EXT_external_memory_metal",
    "VK_KHR_pipeline_binary",
    # Tools and reports that call back or name the process's layers.
    "VK_EXT_tooling_info",
    "VK_EXT_frame_boundary",
}

# Provisional extensions covered all the same: the portability subset, which
# a portability driver (MoltenVK) has and programs (Zink) read to work
# around what Metal lacks. Its structures are in vulkan_beta.h.
PROVISIONAL = {"VK_KHR_portability_subset"}

# Commands fwe's host side answers with code of its own (not a plain call):
# their arguments are still packed by the generated stubs.
HOST_SPECIAL = {
    "vkCreateInstance",
    "vkDestroyInstance",
    "vkEnumerateInstanceExtensionProperties",
    "vkEnumerateInstanceLayerProperties",
    "vkEnumerateInstanceVersion",
    "vkEnumerateDeviceExtensionProperties",
    "vkEnumerateDeviceLayerProperties",
    "vkCreateDevice",
    "vkDestroyDevice",
    "vkGetPhysicalDeviceFeatures2",
    "vkGetPhysicalDeviceFeatures2KHR",
    "vkMapMemory",
    "vkMapMemory2",
    "vkMapMemory2KHR",
    "vkUnmapMemory",
    "vkUnmapMemory2",
    "vkUnmapMemory2KHR",
    "vkWaitForFences",
    "vkWaitSemaphores",
    "vkWaitSemaphoresKHR",
    "vkAcquireNextImageKHR",
    # Null descriptors where the driver has none (null.rs).
    "vkUpdateDescriptorSets",
    "vkUpdateDescriptorSetWithTemplate",
    "vkCmdPushDescriptorSet",
    "vkCmdPushDescriptorSetWithTemplate",
    "vkCmdPushDescriptorSet2",
    "vkCmdPushDescriptorSetWithTemplate2",
    "vkCmdBindVertexBuffers",
    "vkCmdBindVertexBuffers2",
    "vkCreateDescriptorUpdateTemplate",
    "vkDestroyDescriptorUpdateTemplate",
    # Host image copy as the driver can back it (hostcopy.rs).
    "vkGetPhysicalDeviceImageFormatProperties",
    "vkGetPhysicalDeviceImageFormatProperties2",
    "vkGetPhysicalDeviceImageFormatProperties2KHR",
}

# The device's interface, between the guest library and fwe (both written
# from here): one ioctl, `_IOWR('F', 1, struct fwe_vk_call)`, whose record
# is the command's index, its word count, the address of its words and the
# result fwe writes back. Past the commands, fwe's own queries: whether the
# object in word 0 has command word 1 (for `vkGet*ProcAddr`); the object an
# object is of (a physical device's instance, a device's physical device,
# a queue's device); and the family of a queue.
QUERIES = ["HAS", "PARENT", "QUEUE_FAMILY"]
CALL_RECORD = 24
IOCTL_CALL = (3 << 30) | (CALL_RECORD << 16) | (ord("F") << 8) | 1

# Commands that wait with a timeout, and which argument it is: the stub
# turns it into an absolute CLOCK_MONOTONIC deadline (UINT64_MAX stays
# forever), so a wait restarted after a signal ends when it would have.
DEADLINES = {"vkWaitForFences": 4, "vkWaitSemaphores": 2, "vkWaitSemaphoresKHR": 2,
             "vkAcquireNextImageKHR": 2}

C_SCALARS = {
    "void": "void",
    "char": "u8",
    "float": "f32",
    "double": "f64",
    "int8_t": "i8",
    "uint8_t": "u8",
    "int16_t": "i16",
    "uint16_t": "u16",
    "int32_t": "i32",
    "uint32_t": "u32",
    "int64_t": "i64",
    "uint64_t": "u64",
    "size_t": "usize",
    "int": "i32",
}
SIZES = {"u8": 1, "i8": 1, "u16": 2, "i16": 2, "u32": 4, "i32": 4, "f32": 4,
         "u64": 8, "i64": 8, "f64": 8, "usize": 8, "ptr": 8}


# What the generator took for each layout it computed, checked against the
# C headers by the compiler (`check_layouts`): (C expression, value).
CHECKS = []


def text(e):
    """An element's C text, without its `<comment>`s."""
    parts = [e.text or ""]
    for child in e:
        if child.tag != "comment":
            parts.append(text(child))
        parts.append(child.tail or "")
    return "".join(parts)


class Registry:
    def __init__(self, path):
        self.root = ET.parse(path).getroot()
        self.version = self._version()
        self.types = {}
        self.aliases = {}
        self.constants = {}
        self._read_types()
        self._read_constants()
        self.commands = {}
        self._read_commands()
        self.core = self._read_core()
        self.extensions = self._read_extensions()

    def _version(self):
        """The registry's version, from the Vulkan (not Vulkan SC) defines."""
        found = {}
        for t in self.root.find("types"):
            api = t.get("api")
            if t.get("category") != "define" or api and "vulkan" not in api.split(","):
                continue
            name = t.find("name")
            if name is not None:
                found[name.text] = text(t)
        m = re.search(r"VK_MAKE_API_VERSION\(0, (\d+), (\d+), VK_HEADER_VERSION\)",
                      found["VK_HEADER_VERSION_COMPLETE"])
        patch = re.search(r"(\d+)\s*$", found["VK_HEADER_VERSION"].strip()).group(1)
        return f"{m.group(1)}.{m.group(2)}.{patch}"

    def _read_types(self):
        for t in self.root.find("types"):
            api = t.get("api")
            if api and "vulkan" not in api.split(","):
                continue
            name = t.get("name") or (t.find("name").text if t.find("name") is not None else None)
            if not name:
                continue
            if t.get("alias"):
                self.aliases[name] = t.get("alias")
                continue
            self.types[name] = t

    def _read_constants(self):
        for enums in self.root.findall("enums"):
            if enums.get("name") == "API Constants":
                for e in enums:
                    if e.get("value"):
                        v = e.get("value").replace("U", "").replace("(", "").replace(")", "")
                        try:
                            self.constants[e.get("name")] = int(v, 0)
                        except ValueError:
                            pass

    def resolve(self, name):
        while name in self.aliases:
            name = self.aliases[name]
        return name

    def kind(self, name):
        """A type's kind by value: a scalar's ABI name, 'struct', 'fnptr'."""
        if name in C_SCALARS:
            return C_SCALARS[name]
        name = self.resolve(name)
        t = self.types.get(name)
        if t is None:
            return "platform"
        cat = t.get("category")
        if cat == "handle":
            return "ptr" if "VK_DEFINE_HANDLE" in text(t) else "u64"
        if cat == "enum":
            return "i32"
        if cat == "bitmask":
            return "u64" if "VkFlags64" in text(t) else "u32"
        if cat == "basetype":
            inner = t.find("type")
            if inner is not None and "*" not in text(t):
                return self.kind(inner.text)
            return "platform"
        if cat in ("struct", "union"):
            return "struct"
        if cat == "funcpointer":
            return "fnptr"
        return "platform"

    def _read_commands(self):
        for c in self.root.find("commands"):
            api = c.get("api")
            if api and "vulkan" not in api.split(","):
                continue
            if c.get("alias"):
                self.commands[c.get("name")] = {"alias": c.get("alias")}
                continue
            proto = c.find("proto")
            name = proto.find("name").text
            ret = proto.find("type").text
            params = []
            for p in c.findall("param"):
                papi = p.get("api")
                if papi and "vulkan" not in papi.split(","):
                    continue
                t = p.find("type").text
                full = text(p)
                params.append({
                    "name": p.find("name").text,
                    "type": t,
                    "ptr": full.count("*"),
                    "const": full.strip().startswith("const"),
                    "len": p.get("len"),
                    "array": "[" in full,
                })
            self.commands[name] = {"ret": ret, "params": params}

    def command(self, name):
        c = self.commands[name]
        while "alias" in c:
            c = self.commands[c["alias"]]
        return c

    def _read_core(self):
        core = []
        for f in self.root.findall("feature"):
            if "vulkan" not in f.get("api", "").split(","):
                continue
            for req in f.findall("require"):
                for c in req.findall("command"):
                    core.append(c.get("name"))
        return core

    def _read_extensions(self):
        exts = {}
        for e in self.root.find("extensions"):
            if "vulkan" not in (e.get("supported") or "").split(","):
                continue
            cmds = []
            for req in e.findall("require"):
                api = req.get("api")
                if api and "vulkan" not in api.split(","):
                    continue
                if wsi_block(e.get("name"), req):
                    continue
                for c in req.findall("command"):
                    cmds.append(c.get("name"))
            exts[e.get("name")] = {
                "type": e.get("type"),
                "platform": e.get("platform"),
                "provisional": e.get("provisional") == "true",
                "commands": cmds,
            }
        return exts

    # --- Struct layouts (LP64, as clang lays them out on both sides). ----

    def layout(self, name, seen=()):
        """(size, alignment) of a type by value."""
        name = self.resolve(name)
        k = self.kind(name)
        if k in SIZES:
            return SIZES[k], SIZES[k]
        t = self.types.get(name)
        if t is None or t.get("category") not in ("struct", "union"):
            raise ValueError(f"no layout for {name}")
        union = t.get("category") == "union"
        size = align = 0
        bits_left = 0
        for m in t.findall("member"):
            mapi = m.get("api")
            if mapi and "vulkan" not in mapi.split(","):
                continue
            full = text(m)
            mt = m.find("type").text
            if "*" in full:
                msize = malign = 8
            else:
                msize, malign = self.layout(mt, seen + (name,))
            # Bitfields (VkAccelerationStructureInstanceKHR): packed into
            # their 32-bit unit.
            bf = re.search(r":\s*(\d+)", full.split("</name>")[-1] if "</name>" in full else full)
            name_el = m.find("name")
            tail = full[full.find(name_el.text) + len(name_el.text):] if name_el is not None else ""
            bf = re.match(r"\s*:\s*(\d+)", tail)
            if bf:
                bits = int(bf.group(1))
                if bits_left >= bits:
                    bits_left -= bits
                    continue
                bits_left = 32 - bits
            else:
                bits_left = 0
            count = 1
            for dim in re.findall(r"\[([^\]]+)\]", tail):
                enum = m.find("enum")
                if dim.isdigit():
                    count *= int(dim)
                elif enum is not None:
                    count *= self.constants[enum.text]
                else:
                    count *= self.constants[dim]
            msize *= count
            align = max(align, malign)
            if union:
                size = max(size, msize)
            else:
                size = (size + malign - 1) // malign * malign + msize
        align = max(align, 1)
        return (size + align - 1) // align * align, align

    def stype_of(self, name):
        t = self.types.get(self.resolve(name))
        if t is None:
            return None
        for m in t.findall("member"):
            if m.find("name").text == "sType" and m.get("values"):
                return m.get("values").split(",")[0]
        return None

    def enum_values(self):
        """Every enumerant of VkStructureType, with extensions'."""
        values = {}
        for enums in self.root.findall("enums"):
            if enums.get("name") == "VkStructureType":
                for e in enums.findall("enum"):
                    if e.get("value"):
                        values[e.get("name")] = int(e.get("value"))
        def ext_value(e, number):
            off = int(e.get("offset"))
            ext = int(e.get("extnumber") or number)
            v = 1000000000 + (ext - 1) * 1000 + off
            return -v if e.get("dir") == "-" else v
        for f in self.root.findall("feature"):
            for req in f.findall("require"):
                for e in req.findall("enum"):
                    if e.get("extends") == "VkStructureType" and e.get("offset"):
                        values[e.get("name")] = ext_value(e, e.get("extnumber"))
                    elif e.get("extends") == "VkStructureType" and e.get("value"):
                        values[e.get("name")] = int(e.get("value"))
        for x in self.root.find("extensions"):
            for req in x.findall("require"):
                for e in req.findall("enum"):
                    if e.get("extends") != "VkStructureType":
                        continue
                    if e.get("offset"):
                        values[e.get("name")] = ext_value(e, x.get("number"))
                    elif e.get("value"):
                        values[e.get("name")] = int(e.get("value"))
        for x in self.root.find("extensions"):
            for req in x.findall("require"):
                for e in req.findall("enum"):
                    if e.get("extends") == "VkStructureType" and e.get("alias"):
                        values.setdefault(e.get("name"), values.get(e.get("alias")))
        return values


def covered(reg):
    """The commands forwarded (each a stub and a host call), the extensions
    offered, and why any command was left out."""
    exts = {}
    for name, e in reg.extensions.items():
        if name in EXCLUDED_EXTENSIONS:
            continue
        if name in PROVISIONAL:
            pass
        elif e["platform"] or e["provisional"] or e["type"] not in ("instance", "device"):
            continue
        exts[name] = e
    wanted = list(dict.fromkeys(reg.core + [c for e in exts.values() for c in e["commands"]]))
    commands, refused = [], {}
    for name in wanted:
        if name in GUEST_SIDE or name not in reg.commands:
            continue
        c = reg.command(name)
        why = None
        for p in c["params"]:
            k = reg.kind(p["type"])
            if p["ptr"] == 0 and not p["array"] and k in ("struct", "fnptr", "platform"):
                why = f"{p['name']} is a {k} by value"
        if reg.kind(c["ret"]) in ("struct", "fnptr", "platform") and c["ret"] != "void":
            why = f"returns {c['ret']}"
        if c["ret"] == "PFN_vkVoidFunction":
            why = "returns a function"
        if why:
            refused[name] = why
        else:
            commands.append(name)
    # An extension is offered only if all its commands are forwarded, and
    # all its structures are laid out from vk.xml (video coding's come from
    # video.xml, a codec's headers the Mac drivers do not implement).
    exts = {n: e for n, e in exts.items() if all(c in commands or c in GUEST_SIDE for c in e["commands"])}
    for n in list(exts):
        for t in sorted(required_types(reg, {n: exts[n]}, features=False)):
            if reg.types.get(t) is not None and reg.types[t].get("category") in ("struct", "union"):
                try:
                    reg.layout(t)
                except ValueError as err:
                    refused[n] = str(err)
                    del exts[n]
                    break
    keep = set(reg.core) | {c for e in exts.values() for c in e["commands"]}
    commands = [c for c in commands if c in keep]
    return commands, exts, refused


def abi(reg, p):
    if p["ptr"] > 0 or p["array"]:
        return "ptr"
    return reg.kind(p["type"])


def level(reg, name):
    c = reg.command(name)
    first = reg.resolve(c["params"][0]["type"]) if c["params"] else None
    if first in ("VkInstance", "VkPhysicalDevice"):
        return "Instance"
    if first in ("VkDevice", "VkQueue", "VkCommandBuffer"):
        return "Device"
    return "Global"


C_TYPES = {"ptr": "void *", "u8": "uint8_t", "i8": "int8_t", "u16": "uint16_t",
           "i16": "int16_t", "u32": "uint32_t", "i32": "int32_t", "u64": "uint64_t",
           "i64": "int64_t", "usize": "size_t", "f32": "float", "f64": "double",
           "void": "void"}
RS_TYPES = {"ptr": "*mut c_void", "u8": "u8", "i8": "i8", "u16": "u16", "i16": "i16",
            "u32": "u32", "i32": "i32", "u64": "u64", "i64": "i64", "usize": "usize",
            "f32": "f32", "f64": "f64"}


def c_word(k, v):
    if k == "f32":
        return f"fwe_f32_bits({v})"
    if k == "f64":
        return f"fwe_f64_bits({v})"
    if k == "ptr":
        return f"(uint64_t)(uintptr_t){v}"
    if k in ("i8", "i16", "i32"):
        return f"(uint64_t)(uint32_t){v}"
    return f"(uint64_t){v}"


def rs_arg(k, i):
    w = f"a[{i}]"
    return {
        "ptr": f"{w} as usize as *mut c_void",
        "u8": f"{w} as u8", "i8": f"{w} as u8 as i8",
        "u16": f"{w} as u16", "i16": f"{w} as u16 as i16",
        "u32": f"{w} as u32", "i32": f"{w} as u32 as i32",
        "u64": w, "i64": f"{w} as i64", "usize": f"{w} as usize",
        "f32": f"f32::from_bits({w} as u32)", "f64": f"f64::from_bits({w})",
    }[k]


def rs_ret(k):
    return {
        "void": "0", "ptr": "r as usize as u64", "i32": "r as u32 as u64",
        "u32": "u64::from(r)", "u64": "r", "i64": "r as u64", "usize": "r as u64",
    }[k]


def outputs(reg, name, index_of):
    """Rust statements naming the guest memory a command writes, before the
    call: each output pointer's range (for `mm::host_writes`)."""
    c = reg.command(name)
    params = c["params"]
    by_name = {p["name"]: i for i, p in enumerate(params)}
    lines = []
    for i, p in enumerate(params):
        if p["ptr"] == 0 or p["const"] or i == 0 and reg.kind(p["type"]) == "ptr":
            continue
        t = reg.resolve(p["type"])
        k = reg.kind(t)
        if t == "void" and p["ptr"] == 1 and not p["len"]:
            continue  # vkMapMemory's ppData is a pointer to a pointer
        if p["ptr"] > 1:
            esize = 8
        elif k == "struct":
            esize = reg.layout(t)[0]
            CHECKS.append((f"sizeof({t})", esize))
        elif k in SIZES:
            esize = SIZES[k]
        elif t == "void":
            esize = 1
        else:
            continue
        chained = k == "struct" and p["ptr"] == 1 and reg.stype_of(t) is not None
        length = p["len"].split(",")[0] if p["len"] else None
        if length is None:
            count = "1"
        elif length in by_name:
            j = by_name[length]
            q = params[j]
            if q["ptr"] > 0:
                width = SIZES.get(reg.kind(q["type"]), 4)
                count = f"read_count(a[{j}], {width})"
            else:
                count = f"a[{j}]"
        elif length == "null-terminated":
            continue
        else:
            m = re.fullmatch(r"\((\w+) \+ 31\) / 32", length)
            if m and m.group(1) in by_name:
                count = f"(a[{by_name[m.group(1)]}] + 31) / 32"
            else:
                # A member of another parameter (pAllocateInfo->...): the
                # count is the struct's to give; written as one element per
                # its count, bounded by the guest's own buffer.
                mm = re.fullmatch(r"(\w+)->(\w+)", length)
                if mm and mm.group(1) in by_name:
                    sname = reg.resolve(params[by_name[mm.group(1)]]["type"])
                    off = member_offset(reg, sname, mm.group(2))
                    count = f"read_u32(a[{by_name[mm.group(1)]}], {off})"
                else:
                    raise SystemExit(f"{name}: length {length!r} of {p['name']} not understood")
        lines.append(f"            out(a[{i}], {count}, {esize}, {'true' if chained else 'false'});")
    return lines


def member_offset(reg, struct, member):
    t = reg.types[reg.resolve(struct)]
    off = 0
    for m in t.findall("member"):
        mapi = m.get("api")
        if mapi and "vulkan" not in mapi.split(","):
            continue
        full = text(m)
        if "*" in full:
            msize = malign = 8
        else:
            msize, malign = reg.layout(m.find("type").text)
        off = (off + malign - 1) // malign * malign
        if m.find("name").text == member:
            CHECKS.append((f"offsetof({struct}, {member})", off))
            return off
        off += msize
    raise SystemExit(f"{struct} has no member {member}")


def required_types(reg, exts, features=True):
    """The types the covered versions (unless not `features`) and extensions
    bring in, as the headers declare them without any platform's or beta's
    switch."""
    names = set()
    blocks = [f for f in reg.root.findall("feature") if features and "vulkan" in f.get("api", "").split(",")]
    blocks += [x for x in reg.root.find("extensions") if x.get("name") in exts]
    for b in blocks:
        for req in b.findall("require"):
            api = req.get("api")
            if api and "vulkan" not in api.split(","):
                continue
            if b.tag == "extension" and wsi_block(b.get("name"), req):
                continue
            for t in req.findall("type"):
                names.add(reg.resolve(t.get("name")))
    return names


def check_parameters(reg, commands):
    """Each by-value parameter's and result's size, and whether it is a
    float, as the stubs and calls take them, for `check_layouts`."""
    for n in commands:
        cmd = reg.command(n)
        typed = [(p["type"], abi(reg, p)) for p in cmd["params"]]
        if cmd["ret"] != "void":
            typed.append((cmd["ret"], reg.kind(cmd["ret"])))
        for t, k in typed:
            if k == "ptr" or t in C_SCALARS:
                continue
            CHECKS.append((f"sizeof({t})", SIZES[k]))
            CHECKS.append((f"_Generic(({t})0, float: 1, double: 1, default: 0)", int(k in ("f32", "f64"))))


def emit(reg, commands, exts, refused):
    check_parameters(reg, commands)
    index_of = {n: i for i, n in enumerate(commands)}
    most = max(len(reg.command(n)["params"]) for n in commands)

    c = []
    c.append(f"/* @generated by tools/gen-vulkan.py from vk.xml {reg.version}; it MUST NOT be edited by hand. */")
    c.append('#include "fwe_vk.h"')
    h = [
        f"/* @generated by tools/gen-vulkan.py from vk.xml {reg.version}; it MUST NOT be edited by hand. */",
        "/* The device's interface, fwe's side of which is crates/kernel/src/vulkan. */",
        "#pragma once",
        "",
        "/* The one ioctl: _IOWR('F', 1, struct fwe_vk_call). */",
        f"#define FWE_VK_IOCTL_CALL 0x{IOCTL_CALL:x}u",
        f"#define FWE_VK_CALL_RECORD {CALL_RECORD}",
        "/* fwe's queries, past the commands: whether an object has a command,",
        " * the object it is of, a queue's family. */",
    ] + [f"#define FWE_VK_{q} {len(commands) + i}u" for i, q in enumerate(QUERIES)] + [
        f"#define FWE_VK_COMMANDS {len(commands)}u",
        f'#define FWE_VK_REGISTRY "{reg.version}"',
        "",
        "/* Each command's index. */",
    ] + [f"#define FWE_VK_CMD_{n} {i}u" for i, n in enumerate(commands)]
    h.append("")
    h.append("/* Each command as the driver has it (its stub), and the window systems'")
    h.append(" * commands the library answers itself (wsi.c): the library's. */")
    h.append("#ifdef FWE_VK_LIBRARY")
    for n in commands:
        cmd = reg.command(n)
        rk = "void" if cmd["ret"] == "void" else reg.kind(cmd["ret"])
        params = ", ".join(C_TYPES[abi(reg, p)] for p in cmd["params"]) or "void"
        h.append(f"{C_TYPES[rk]} fwe_host_{n}({params});")
        if use_of(reg, n, exts) == "WSI":
            h.append(f"{C_TYPES[rk]} fwe_wsi_{n}({params});")
    h.append("#endif")
    c.append("")
    for i, n in enumerate(commands):
        cmd = reg.command(n)
        rk = "void" if cmd["ret"] == "void" else reg.kind(cmd["ret"])
        ks = [abi(reg, p) for p in cmd["params"]]
        params = ", ".join(f"{C_TYPES[k]} a{j}" for j, k in enumerate(ks)) or "void"
        c.append(f"{C_TYPES[rk]} fwe_host_{n}(%s) {{" % params)
        words = ", ".join(c_word(k, f"a{j}") for j, k in enumerate(ks))
        c.append(f"    uint64_t w[{max(len(ks), 1)}] = {{{words or '0'}}};")
        if n in DEADLINES:
            c.append(f"    w[{DEADLINES[n]}] = fwe_vk_deadline(a{DEADLINES[n]});")
        n_words = len(ks)
        if rk == "void":
            c.append(f"    fwe_vk_call({i}, w, {n_words}, 0);")
        else:
            failed = "0"
            if cmd["ret"] == "VkResult":
                failed = "(uint64_t)(int64_t)" + ("FWE_VK_INIT_FAILED" if level(reg, n) != "Device" else "FWE_VK_LOST")
            c.append(f"    return ({C_TYPES[rk]})fwe_vk_call({i}, w, {n_words}, {failed});")
        c.append("}")
    c.append("")
    c.append("/* Every command's stub by name, sorted for a binary search. */")
    c.append("const struct fwe_vk_entry fwe_vk_entries[] = {")
    names = []
    for n in commands:
        names.append((n, n))
    for alias, target in reg.commands.items():
        if "alias" in target and target["alias"] in index_of and alias not in index_of:
            names.append((alias, target["alias"]))
    for name, target in sorted(names):
        use = use_of(reg, target, exts)
        fn = f"fwe_wsi_{target}" if use == "WSI" else f"fwe_host_{target}"
        c.append(f'    {{"{name}", (fwe_vk_fn){fn}, FWE_VK_{level(reg, target).upper()}, FWE_VK_USE_{use}, {index_of[target]}}},')
    c.append("};")
    c.append(f"const unsigned fwe_vk_entry_count = {len(names)};")
    c.append("")

    rs = []
    rs.append(f"// @generated by tools/gen-vulkan.py from vk.xml {reg.version}; it MUST NOT be edited by hand.")
    rs.append("#![allow(clippy::all, clippy::pedantic, non_snake_case, unused_variables)]")
    rs.append("")
    rs.append("use super::Level;")
    rs.append("use std::ffi::c_void;")
    rs.append("")
    rs.append(f'/// The registry these were made from.\npub const REGISTRY: &str = "{reg.version}";')
    rs.append(f"/// The most arguments a command has.\npub const MOST_ARGS: usize = {most};")
    rs.append(f"/// How many commands there are.\npub const COMMANDS: usize = {len(commands)};")
    rs.append(f"/// The device's one ioctl: `_IOWR('F', 1, struct fwe_vk_call)`.\npub const IOCTL_CALL: u64 = {IOCTL_CALL:#x};")
    rs.append(f"/// The size of its record: command, word count, words' address, result.\npub const CALL_RECORD: usize = {CALL_RECORD};")
    rs.append("/// fwe's queries, past the commands: whether an object has a command,")
    rs.append("/// the object it is of, a queue's family.")
    for i, q in enumerate(QUERIES):
        rs.append(f"pub const {q}: u32 = COMMANDS as u32 + {i};")
    rs.append("")
    rs.append("/// The argument of command `index` that its stub made an absolute")
    rs.append("/// `CLOCK_MONOTONIC` deadline, if it waits with a timeout.")
    rs.append("pub fn deadline_arg(index: usize) -> Option<usize> {")
    rs.append("    match NAMES[index] {")
    for name, arg in sorted(DEADLINES.items()):
        rs.append(f'        "{name}" => Some({arg}),')
    rs.append("        _ => None,")
    rs.append("    }")
    rs.append("}")
    rs.append("")
    rs.append("/// Each command's name, by index.")
    rs.append("pub static NAMES: [&str; COMMANDS] = [")
    for n in commands:
        rs.append(f'    "{n}",')
    rs.append("];")
    rs.append("")
    rs.append("/// Each command's level (what its first argument is), by index.")
    rs.append("pub static LEVELS: [Level; COMMANDS] = [")
    for n in commands:
        rs.append(f"    Level::{level(reg, n)},")
    rs.append("];")
    rs.append("")
    rs.append("/// Whether each command returns a `VkResult`, by index.")
    rs.append("pub static RESULTS: [bool; COMMANDS] = [")
    for n in commands:
        rs.append(f"    {'true' if reg.command(n)['ret'] == 'VkResult' else 'false'},")
    rs.append("];")
    rs.append("")
    rs.append("/// The commands fwe answers with code of its own, by index.")
    rs.append("pub static SPECIAL: [bool; COMMANDS] = [")
    for n in commands:
        rs.append(f"    {'true' if n in HOST_SPECIAL else 'false'},")
    rs.append("];")
    rs.append("")
    rs.append("/// Each command's index, by its name.")
    rs.append("#[allow(non_upper_case_globals)]")
    rs.append("pub mod cmd {")
    for i, n in enumerate(commands):
        rs.append(f"    pub const {n}: usize = {i};")
    rs.append("}")
    rs.append("")
    rs.append("/// Each command's index by name.")
    rs.append("pub fn index(name: &str) -> Option<usize> {")
    rs.append("    NAMES.iter().position(|n| *n == name)")
    rs.append("}")
    rs.append("")
    rs.append("/// Call command `index` at `f`, the Mac driver's function for it, with")
    rs.append("/// the stub's words `a`, typed as the command is.")
    rs.append("///")
    rs.append("/// # Safety")
    rs.append("///")
    rs.append("/// `f` is the driver's function for command `index`, and `a` holds that")
    rs.append("/// command's arguments as the guest's stub packed them.")
    rs.append("pub unsafe fn call(index: usize, f: *const c_void, a: &[u64; MOST_ARGS]) -> u64 {")
    rs.append("    // SAFETY: the caller's: `f` has the type of command `index`.")
    rs.append("    unsafe {")
    rs.append("        match index {")
    for i, n in enumerate(commands):
        cmd = reg.command(n)
        rk = "void" if cmd["ret"] == "void" else reg.kind(cmd["ret"])
        ks = [abi(reg, p) for p in cmd["params"]]
        sig = ", ".join(RS_TYPES[k] for k in ks)
        ret = "" if rk == "void" else f" -> {RS_TYPES[rk]}"
        # An allocator is the guest's functions, which host code never
        # calls: the driver allocates for itself.
        args = ", ".join("std::ptr::null_mut()" if cmd["params"][j]["type"] == "VkAllocationCallbacks"
                         else rs_arg(k, j) for j, k in enumerate(ks))
        rs.append(f"            {i} => {{")
        rs.append(f'                let f: unsafe extern "C" fn({sig}){ret} = std::mem::transmute(f);')
        if rk == "void":
            rs.append(f"                f({args});")
            rs.append("                0")
        else:
            rs.append(f"                let r = f({args});")
            rs.append(f"                {rs_ret(rk)}")
        rs.append("            }")
    rs.append("            _ => unreachable!(\"no command {index}\"),")
    rs.append("        }")
    rs.append("    }")
    rs.append("}")
    rs.append("")
    rs.append("/// The guest memory command `index` writes, before it is called: each")
    rs.append("/// output's address, element count and size, and whether its elements")
    rs.append("/// carry `pNext` chains the driver writes too.")
    rs.append("pub fn outputs(")
    rs.append("    index: usize,")
    rs.append("    a: &[u64; MOST_ARGS],")
    rs.append("    read_count: impl Fn(u64, u64) -> u64,")
    rs.append("    read_u32: impl Fn(u64, u64) -> u64,")
    rs.append("    mut out: impl FnMut(u64, u64, u64, bool),")
    rs.append(") {")
    rs.append("    match index {")
    for i, n in enumerate(commands):
        lines = outputs(reg, n, index_of)
        if lines:
            rs.append(f"        {i} => {{")
            rs.extend(lines)
            rs.append("        }")
    rs.append("        _ => {}")
    rs.append("    }")
    rs.append("}")
    rs.append("")
    values = reg.enum_values()
    sizes = {}
    for name in sorted(required_types(reg, exts)):
        t = reg.types.get(name)
        if t is None or t.get("category") != "struct":
            continue
        st = reg.stype_of(name)
        if st and st in values:
            sizes[values[st]] = (reg.layout(name)[0], name)
            CHECKS.append((f"sizeof({name})", sizes[values[st]][0]))
            CHECKS.append((f"{st}", values[st]))
    rs.append("/// The size of the structure of `VkStructureType` `stype`.")
    rs.append("pub fn struct_size(stype: u32) -> Option<u64> {")
    rs.append("    Some(match stype {")
    for v in sorted(sizes):
        size, name = sizes[v]
        rs.append(f"        {v} => {size}, // {name}")
    rs.append("        _ => return None,")
    rs.append("    })")
    rs.append("}")
    rs.append("")
    rs.append("/// The driver's extensions whose commands are all covered, and their")
    rs.append("/// kind (the window systems' are the guest library's).")
    rs.append("pub static EXTENSIONS: &[(&str, Level)] = &[")
    for n in sorted(set(exts) - HOST_WSI):
        lv = "Instance" if exts[n]["type"] == "instance" else "Device"
        rs.append(f'    ("{n}", Level::{lv}),')
    rs.append("];")
    rs.append("")
    rs.append("/// Commands of covered versions and extensions left out, and why.")
    rs.append("pub static REFUSED: &[(&str, &str)] = &[")
    for n in sorted(refused):
        rs.append(f'    ("{n}", "{refused[n]}"),')
    rs.append("];")
    return "\n".join(h) + "\n", "\n".join(c) + "\n", "\n".join(rs) + "\n"


def check_layouts(include):
    """Every size, offset and structure-type value the generator computed,
    asserted against the C headers of the same registry, so that the
    compiler, which lays the structures out for both sides, agrees."""
    src = ["#include <stddef.h>", "#define VK_ENABLE_BETA_EXTENSIONS", "#include <vulkan/vulkan.h>"]
    for i, (expr, value) in enumerate(dict.fromkeys(CHECKS)):
        src.append(f'_Static_assert((long long)({expr}) == {value}LL, "{expr} is {value}");')
    r = subprocess.run(["clang", "-fsyntax-only", "-ferror-limit=0", "-x", "c", "-I", include, "-"],
                       input="\n".join(src) + "\n", capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("layouts disagree with the headers:\n" + r.stderr[:6000])
    return len(set(CHECKS))


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else None
    if path is None:
        prefix = subprocess.run(["brew", "--prefix"], capture_output=True, text=True, check=True).stdout.strip()
        path = os.path.join(prefix, "share", "vulkan", "registry", "vk.xml")
    reg = Registry(path)
    commands, exts, refused = covered(reg)
    h, c, rs = emit(reg, commands, exts, refused)
    # The headers installed beside the registry: <prefix>/share/vulkan/registry/vk.xml
    # and <prefix>/include/vulkan/vulkan.h.
    prefix = os.path.abspath(os.path.join(os.path.dirname(path), "..", "..", ".."))
    include = os.path.join(prefix, "include")
    checked = check_layouts(include)
    os.makedirs(os.path.dirname(OUT_C), exist_ok=True)
    os.makedirs(os.path.dirname(OUT_RS), exist_ok=True)
    with open(OUT_C, "w") as f:
        f.write(c)
    with open(OUT_H, "w") as f:
        f.write(h)
    with open(OUT_RS, "w") as f:
        f.write(rs)
    print(f"vk.xml {reg.version}: {len(commands)} commands, {len(exts)} extensions, "
          f"{len(refused)} refused; {checked} layouts checked against the headers")
    for n, why in sorted(refused.items()):
        print(f"  refused {n}: {why}")


if __name__ == "__main__":
    main()
