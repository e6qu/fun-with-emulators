#!/usr/bin/env python3
"""The X server's screen as a PNG:
`shot.py <libX11> <display> <out.png> [<x> <y> <w> <h>]`.

Grabs the root window of `display` (a 24- or 32-bit TrueColor screen, as
Xvfb's is) through libX11 (`libX11`, the host's), or the rectangle of it
given, and writes it to `out.png`. Prints its size and how many of its
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


def grab(lib, display, rect=None):
    x = ctypes.CDLL(lib)
    x.XOpenDisplay.restype = ctypes.c_void_p
    x.XOpenDisplay.argtypes = [ctypes.c_char_p]
    x.XDefaultRootWindow.restype = ctypes.c_ulong
    x.XDefaultRootWindow.argtypes = [ctypes.c_void_p]
    x.XGetImage.restype = ctypes.POINTER(XImage)
    x.XGetImage.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_int, ctypes.c_int,
                            ctypes.c_uint, ctypes.c_uint, ctypes.c_ulong, ctypes.c_int]
    x.XDisplayWidth.argtypes = x.XDisplayHeight.argtypes = [ctypes.c_void_p, ctypes.c_int]
    d = x.XOpenDisplay(display.encode())
    if not d:
        sys.exit(f"cannot open display {display}")
    left, top = 0, 0
    w, h = x.XDisplayWidth(d, 0), x.XDisplayHeight(d, 0)
    if rect:
        left, top, w, h = rect
    img = x.XGetImage(d, x.XDefaultRootWindow(d), left, top, w, h, 0xFFFFFFFF, 2).contents
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
