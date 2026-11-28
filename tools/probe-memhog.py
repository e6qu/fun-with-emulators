#!/usr/bin/env python3
# Probe: hold `gb` GiB of memory and keep touching it (a page in every 16
# KiB), so the host compresses and pages out others' memory.
import sys, time
gb = float(sys.argv[1])
chunks = [bytearray(64 << 20) for _ in range(int(gb * 16))]
while True:
    for c in chunks:
        for i in range(0, len(c), 16384):
            c[i] = (c[i] + 1) & 255
    time.sleep(0.05)
