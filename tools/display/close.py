#!/usr/bin/env python3
"""Ask an X window to close, as a window manager's close button does:
`close.py <libX11> <display> <window id>`.

Sends the window a `WM_PROTOCOLS` client message holding
`WM_DELETE_WINDOW` (ICCCM 4.2.8.1) through libX11 (`libX11`, the host's).
With no window manager, as on a bare Xvfb, nothing else delivers that
request (xdotool's `windowquit` asks a window manager to, by
`_NET_CLOSE_WINDOW`).
"""

import ctypes
import sys


class XClientMessageEvent(ctypes.Structure):
    _fields_ = [("type", ctypes.c_int), ("serial", ctypes.c_ulong),
                ("send_event", ctypes.c_int), ("display", ctypes.c_void_p),
                ("window", ctypes.c_ulong), ("message_type", ctypes.c_ulong),
                ("format", ctypes.c_int), ("l", ctypes.c_long * 5)]


class XEvent(ctypes.Union):
    # Xlib's XEvent: 24 longs, of which a client message is one view.
    _fields_ = [("xclient", XClientMessageEvent), ("pad", ctypes.c_long * 24)]


CLIENT_MESSAGE = 33
CURRENT_TIME = 0
NO_EVENT_MASK = 0


def main():
    lib, display, window = sys.argv[1], sys.argv[2], int(sys.argv[3], 0)
    x = ctypes.CDLL(lib)
    x.XOpenDisplay.restype = ctypes.c_void_p
    x.XOpenDisplay.argtypes = [ctypes.c_char_p]
    x.XInternAtom.restype = ctypes.c_ulong
    x.XInternAtom.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
    x.XSendEvent.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_int, ctypes.c_long,
                             ctypes.POINTER(XEvent)]
    x.XFlush.argtypes = x.XCloseDisplay.argtypes = [ctypes.c_void_p]
    d = x.XOpenDisplay(display.encode())
    if not d:
        sys.exit(f"cannot open display {display}")
    ev = XEvent()
    ev.xclient.type = CLIENT_MESSAGE
    ev.xclient.window = window
    ev.xclient.message_type = x.XInternAtom(d, b"WM_PROTOCOLS", 0)
    ev.xclient.format = 32
    ev.xclient.l[0] = x.XInternAtom(d, b"WM_DELETE_WINDOW", 0)
    ev.xclient.l[1] = CURRENT_TIME
    if not x.XSendEvent(d, window, 0, NO_EVENT_MASK, ctypes.byref(ev)):
        sys.exit("XSendEvent failed")
    x.XFlush(d)
    x.XCloseDisplay(d)


if __name__ == "__main__":
    main()
