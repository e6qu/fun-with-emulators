#!/usr/bin/env python3
"""The X server's screen as a PNG:
`shot.py <libX11> <display> <out.png> [<x> <y> <w> <h> | window <id>]`.

Grabs the root window of `display` (a 24- or 32-bit TrueColor screen, as
Xvfb's is) through libX11 (`libX11`, the host's), or the rectangle of it
given, as much of it as is on the screen (a window can reach past it),
or with `window`, window `id` itself (XQuartz's root shows none of its
windows: each keeps its own pixels), as much of it as is on the screen
(X gives no pixels of a window's part beyond it), and writes it to
`out.png`. An X error ends it with the screen's and the window's
geometry. Prints its size and how many of its
pixels are not its most common colour (what was drawn on the
background); then `colour <rrggbb> <n>` for each colour of the whole
image, most common first (the first 32), and `digest <hex>`, a hash of
every pixel, which tells two images apart.
"""

import collections
import ctypes
import hashlib
import struct
import sys
import zlib


class XImage(ctypes.Structure):
    # The leading fields of Xlib's XImage, as far as the pixels' layout.
    _fields_ = [("width", ctypes.c_int), ("height", ctypes.c_int),
                ("xoffset", ctypes.c_int), ("format", ctypes.c_int),
                ("data", ctypes.c_void_p), ("byte_order", ctypes.c_int),
                ("bitmap_unit", ctypes.c_int), ("bitmap_bit_order", ctypes.c_int),
                ("bitmap_pad", ctypes.c_int), ("depth", ctypes.c_int),
                ("bytes_per_line", ctypes.c_int), ("bits_per_pixel", ctypes.c_int)]


def grab(lib, display, rect=None, window=None):
    x = ctypes.CDLL(lib)
    x.XOpenDisplay.restype = ctypes.c_void_p
    x.XOpenDisplay.argtypes = [ctypes.c_char_p]
    x.XDefaultRootWindow.restype = ctypes.c_ulong
    x.XDefaultRootWindow.argtypes = [ctypes.c_void_p]
    x.XGetImage.restype = ctypes.POINTER(XImage)
    x.XGetImage.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_int, ctypes.c_int,
                            ctypes.c_uint, ctypes.c_uint, ctypes.c_ulong, ctypes.c_int]
    x.XDisplayWidth.argtypes = x.XDisplayHeight.argtypes = [ctypes.c_void_p, ctypes.c_int]
    x.XTranslateCoordinates.argtypes = [
        ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_int, ctypes.c_int,
        ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_ulong)]
    x.XSync.argtypes = [ctypes.c_void_p, ctypes.c_int]
    # An X error is kept, not Xlib's exit: the image is then absent.
    errors = []

    @ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(XErrorEvent))
    def on_error(_display, event):
        e = event.contents
        errors.append(f"X error {e.error_code} of request {e.request_code}")
        return 0
    x.XSetErrorHandler(on_error)
    d = x.XOpenDisplay(display.encode())
    if not d:
        sys.exit(f"cannot open display {display}")
    sw, sh = x.XDisplayWidth(d, 0), x.XDisplayHeight(d, 0)
    left, top, w, h = 0, 0, sw, sh
    drawable = root = x.XDefaultRootWindow(d)
    where = f"the {sw}x{sh} screen"
    if window is not None:
        # The window's place on the screen, and its part there.
        rx, ry, child = ctypes.c_int(), ctypes.c_int(), ctypes.c_ulong()
        x.XTranslateCoordinates(d, window, root, 0, 0, ctypes.byref(rx), ctypes.byref(ry),
                                ctypes.byref(child))
        ww, wh = rect[2:]
        drawable, rx, ry = window, rx.value, ry.value
        left, top = max(0, -rx), max(0, -ry)
        w, h = min(ww, sw - rx) - left, min(wh, sh - ry) - top
        where = f"window {window:#x}, {ww}x{wh} at {rx},{ry} of the {sw}x{sh} screen"
        if w <= 0 or h <= 0:
            sys.exit(f"{where}: none of it is on the screen")
    elif rect:
        x0, y0, rw, rh = rect
        left, top = max(0, x0), max(0, y0)
        w, h = min(sw, x0 + rw) - left, min(sh, y0 + rh) - top
        if w <= 0 or h <= 0:
            sys.exit(f"{rw}x{rh} at {x0},{y0} is off the {sw}x{sh} screen")
    got = x.XGetImage(d, drawable, left, top, w, h, 0xFFFFFFFF, 2)
    x.XSync(d, 0)
    if not got or errors:
        sys.exit(f"no image of {w}x{h} at {left},{top} of {where}: {errors}")
    img = got.contents
    if img.bits_per_pixel != 32:
        sys.exit(f"{img.bits_per_pixel} bits a pixel: only 32 are read")
    raw = ctypes.string_at(img.data, img.bytes_per_line * h)
    rows = []
    for y in range(h):
        line = raw[y * img.bytes_per_line:y * img.bytes_per_line + 4 * w]
        # BGRX (least significant byte first) to RGB.
        rgb = bytearray(3 * w)
        rgb[0::3], rgb[1::3], rgb[2::3] = line[2::4], line[1::4], line[0::4]
        rows.append(bytes(rgb))
    return w, h, rows


class XErrorEvent(ctypes.Structure):
    _fields_ = [("type", ctypes.c_int), ("display", ctypes.c_void_p),
                ("resourceid", ctypes.c_ulong), ("serial", ctypes.c_ulong),
                ("error_code", ctypes.c_ubyte), ("request_code", ctypes.c_ubyte),
                ("minor_code", ctypes.c_ubyte)]


class XWindowAttributes(ctypes.Structure):
    # The leading fields of Xlib's XWindowAttributes, as far as the size;
    # room for the rest.
    _fields_ = [("x", ctypes.c_int), ("y", ctypes.c_int), ("width", ctypes.c_int),
                ("height", ctypes.c_int), ("rest", ctypes.c_char * 256)]


def window_size(lib, display, window):
    x = ctypes.CDLL(lib)
    x.XOpenDisplay.restype = ctypes.c_void_p
    x.XOpenDisplay.argtypes = [ctypes.c_char_p]
    x.XGetWindowAttributes.argtypes = [ctypes.c_void_p, ctypes.c_ulong,
                                       ctypes.POINTER(XWindowAttributes)]
    d = x.XOpenDisplay(display.encode())
    if not d:
        sys.exit(f"cannot open display {display}")
    a = XWindowAttributes()
    if not x.XGetWindowAttributes(d, window, ctypes.byref(a)):
        sys.exit(f"no window {window:#x}")
    return a.width, a.height


def png(path, w, h, rows):
    def chunk(kind, data):
        c = kind + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)
    body = zlib.compress(b"".join(b"\0" + r for r in rows), 6)
    with open(path, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
                + chunk(b"IDAT", body) + chunk(b"IEND", b""))


def main():
    lib, display, out = sys.argv[1:4]
    if sys.argv[4:5] == ["window"]:
        # The window's size, from its attributes.
        window = int(sys.argv[5], 0)
        w, h, rows = grab(lib, display, (0, 0) + window_size(lib, display, window), window)
    else:
        rect = tuple(int(v) for v in sys.argv[4:8]) if len(sys.argv) >= 8 else None
        w, h, rows = grab(lib, display, rect)
    png(out, w, h, rows)
    counts = collections.Counter(r[i:i + 3] for r in rows for i in range(0, 3 * w, 3))
    background, n = counts.most_common(1)[0]
    drawn = sum(counts.values()) - n
    print(f"{w}x{h}, background #{background.hex()}, {drawn} of {sum(counts.values())} "
          f"pixels drawn")
    for colour, k in counts.most_common(32):
        print(f"colour {colour.hex()} {k}")
    print(f"digest {hashlib.sha256(b''.join(rows)).hexdigest()}")


if __name__ == "__main__":
    main()
