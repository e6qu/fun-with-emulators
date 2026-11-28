#!/usr/bin/env python3
# A native process's own wake-up lateness: 2 ms sleeps, each wake more
# than 8 ms late logged with its CLOCK_MONOTONIC time in us.
import time, sys
out = open(sys.argv[1], "w", buffering=1)
mono = lambda: time.clock_gettime_ns(time.CLOCK_MONOTONIC) // 1000
while True:
    t = mono()
    time.sleep(0.002)
    late = mono() - t - 2000
    if late > 8000:
        out.write(f"{t} late {late}\n")
