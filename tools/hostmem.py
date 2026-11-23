"""The host's memory, watched while fwe's tests and benchmarks run.

A Mac short of memory can panic: its memory compressor once did, over a
wired index of fwe's objects' pages that had grown to half the host's
memory. So a run stops, saying what holds the memory and ending its own
processes, before the host is out of it: below `LEVEL_FLOOR` of its memory
available (macOS's `kern.memorystatus_level`, what `memory_pressure`
shows) or above `WIRED_CEILING` of it wired (memory never compressed or
paged out). The Rust tests check the same bounds before and while each
guest runs (`crates/fwe/tests/guests.rs`).
"""

import os
import re
import signal
import subprocess
import threading
import time

# Percent of the host's memory available below which a run stops.
LEVEL_FLOOR = 20

# Percent of the host's memory wired above which a run stops.
WIRED_CEILING = 50


def state():
    """The host's memory now: available (%), wired (%), free, compressed
    and swapped (MB)."""
    out = subprocess.run(["vm_stat"], capture_output=True, text=True).stdout
    page = int(re.search(r"page size of (\d+)", out).group(1))
    pages = {k.strip(): int(v.strip().rstrip(".")) for k, v in
             (line.split(":", 1) for line in out.splitlines()[1:] if ":" in line)}
    numbers = subprocess.run(["sysctl", "-n", "kern.memorystatus_level", "hw.memsize"],
                             capture_output=True, text=True).stdout.split()
    level, total = int(numbers[0]), int(numbers[1])
    swap = subprocess.run(["sysctl", "-n", "vm.swapusage"], capture_output=True, text=True).stdout
    used = re.search(r"used = ([\d.]+)M", swap)
    mb = lambda n: n * page // (1 << 20)
    return {
        "level": level,
        "wired": pages.get("Pages wired down", 0) * page * 100 // total,
        "free": mb(pages.get("Pages free", 0) + pages.get("Pages speculative", 0)),
        "compressed": mb(pages.get("Pages occupied by compressor", 0)),
        "swap": float(used.group(1)) if used else 0.0,
    }


def describe(s):
    return (f"available {s['level']}%, wired {s['wired']}%, free {s['free']} MB, "
            f"compressed {s['compressed']} MB, swap {s['swap']:.0f} MB")


def short(s):
    """Why the host is too short of memory to go on, if it is."""
    if s["level"] < LEVEL_FLOOR or s["wired"] > WIRED_CEILING:
        return (f"the host is short of memory: {describe(s)} (floor {LEVEL_FLOOR}% available, "
                f"ceiling {WIRED_CEILING}% wired)")
    return None


def report():
    """What holds the host's memory: the processes holding the most, and
    the host's page counts."""
    ps = subprocess.run(["ps", "-axo", "pid=,ppid=,rss=,vsz=,command="], capture_output=True,
                        text=True).stdout.splitlines()
    biggest = sorted(ps, key=lambda l: -int(l.split()[2]) if len(l.split()) > 2 else 0)[:30]
    print("processes holding the most memory (pid, parent, resident KB, virtual KB, command):")
    for line in biggest:
        print("    " + line[:300])
    print(subprocess.run(["vm_stat"], capture_output=True, text=True).stdout, flush=True)


def end_processes(pattern):
    """SIGKILL every process whose command line matches `pattern` (an
    extended regular expression, as `pgrep -f` takes): how many."""
    found = subprocess.run(["pgrep", "-f", pattern], capture_output=True, text=True)
    pids = [int(p) for p in found.stdout.split() if int(p) > 0 and int(p) != os.getpid()]
    for pid in pids:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    return len(pids)


class Guard(threading.Thread):
    """Twice a second, the host's memory, given to `seen` (with the time)
    if set; once it is short, `on_short` is called with why, and the
    guard stops."""

    def __init__(self, on_short, seen=None):
        super().__init__(daemon=True)
        self.on_short = on_short
        self.seen = seen
        self.stopped = threading.Event()

    def run(self):
        while not self.stopped.wait(0.5):
            s = state()
            if self.seen:
                self.seen(time.strftime("%H:%M:%S"), s)
            why = short(s)
            if why:
                self.on_short(why)
                return

    def stop(self):
        self.stopped.set()
