#!/usr/bin/env python3
"""PROBE (temporary): the key and focus events an X window gets, for
`seconds`: `watch.py <libX11> <display> <window id> <seconds>`."""

import ctypes
import select
import sys
import time


class XAnyKey(ctypes.Structure):
    _fields_ = [("type", ctypes.c_int), ("serial", ctypes.c_ulong),
                ("send_event", ctypes.c_int), ("display", ctypes.c_void_p),
                ("window", ctypes.c_ulong), ("root", ctypes.c_ulong),
                ("subwindow", ctypes.c_ulong), ("time", ctypes.c_ulong),
                ("x", ctypes.c_int), ("y", ctypes.c_int), ("x_root", ctypes.c_int),
                ("y_root", ctypes.c_int), ("state", ctypes.c_uint),
                ("keycode", ctypes.c_uint), ("same_screen", ctypes.c_int)]


class XFocus(ctypes.Structure):
    _fields_ = [("type", ctypes.c_int), ("serial", ctypes.c_ulong),
                ("send_event", ctypes.c_int), ("display", ctypes.c_void_p),
                ("window", ctypes.c_ulong), ("mode", ctypes.c_int), ("detail", ctypes.c_int)]


class XEvent(ctypes.Union):
    _fields_ = [("type", ctypes.c_int), ("xkey", XAnyKey), ("xfocus", XFocus),
                ("pad", ctypes.c_long * 24)]


NAMES = {2: "KeyPress", 3: "KeyRelease", 9: "FocusIn", 10: "FocusOut"}


def main():
    lib, display, window, seconds = sys.argv[1], sys.argv[2], int(sys.argv[3], 0), float(sys.argv[4])
    x = ctypes.CDLL(lib)
    x.XOpenDisplay.restype = ctypes.c_void_p
    x.XOpenDisplay.argtypes = [ctypes.c_char_p]
    x.XSelectInput.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_long]
    x.XPending.argtypes = x.XConnectionNumber.argtypes = x.XFlush.argtypes = [ctypes.c_void_p]
    x.XNextEvent.argtypes = [ctypes.c_void_p, ctypes.POINTER(XEvent)]
    x.XKeycodeToKeysym.argtypes = [ctypes.c_void_p, ctypes.c_ubyte, ctypes.c_int]
    x.XKeycodeToKeysym.restype = ctypes.c_ulong
    x.XKeysymToString.argtypes = [ctypes.c_ulong]
    x.XKeysymToString.restype = ctypes.c_char_p
    d = x.XOpenDisplay(display.encode())
    if not d:
        sys.exit(f"cannot open display {display}")
    # KeyPress, KeyRelease, FocusChange.
    x.XSelectInput(d, window, (1 << 0) | (1 << 1) | (1 << 21))
    x.XFlush(d)
    print("watching", hex(window), flush=True)
    end = time.time() + seconds
    fd = x.XConnectionNumber(d)
    ev = XEvent()
    while time.time() < end:
        if not x.XPending(d):
            select.select([fd], [], [], 0.1)
            continue
        x.XNextEvent(d, ctypes.byref(ev))
        name = NAMES.get(ev.type, str(ev.type))
        if ev.type in (2, 3):
            k = ev.xkey
            sym = x.XKeysymToString(x.XKeycodeToKeysym(d, k.keycode, 0))
            print(f"{time.time():.3f} {name} window {k.window:#x} sub {k.subwindow:#x} "
                  f"keycode {k.keycode} ({sym}) state {k.state:#x} send {k.send_event}", flush=True)
        elif ev.type in (9, 10):
            f = ev.xfocus
            print(f"{time.time():.3f} {name} window {f.window:#x} mode {f.mode} detail {f.detail}",
                  flush=True)


if __name__ == "__main__":
    main()
