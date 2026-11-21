#!/usr/bin/env python3
"""fwe's benchmarks: startup, system calls, fork/exec, threads, a C
project's build and programs' realistic workloads, under fwe, natively on
macOS and natively on Linux.

    run.py linux --bench BENCH --cache DIR --xvfb XVFB --out linux.json
        On arm64 Linux: BENCH (guests/c/bench.c, built static-pie) runs
        natively; Lua is built, and the workloads run, in an Alpine 3.24
        container (docker).

    run.py macos --fwe FWE --bench BENCH --native NATIVE --brew PREFIX
                 --cache DIR --xvfb XVFB [--linux linux.json] [--no-build]
                 --out macos.json
        On macOS: BENCH (the Linux build) runs under FWE; NATIVE (the same
        source built for macOS) runs natively. Lua is built with clang under
        FWE in an Alpine root (guests/alpine/fetch/clang.txt, fetched into
        DIR), and natively with Homebrew's clang of the same release (under
        PREFIX); the workloads (tools/bench/workloads: Lua, Python, SQLite,
        git and xz) run under FWE in an Alpine root of those programs
        (guests/alpine/fetch/workloads.txt) and natively with Homebrew's
        builds of them, each side's output checked against the other's.
        `--linux-vm` adds the same benchmarks run in a Linux VM on the
        same Mac (tools/bench/vm.sh), with fwe's ratio to them; `--fwe-vm`
        those of a run under fwe's VM backend (`fwe --vm`).
        With the Linux results, a table of all three is printed (and
        appended to $GITHUB_STEP_SUMMARY). `--no-build` leaves the build and
        the workloads out (Alpine's programs run only in CI). It fails when
        a figure of fwe's exceeds its budget against macOS's (BUDGETS) or
        its own limit (LIMITS), or a computing program's share of fwe's its
        own (SHARE_BUDGETS).

The X benchmarks talk to an X server run here (XVFB, an Xvfb), the same
one for fwe's side and the native one.

Each figure is the best of several runs: the machines are shared, and the
best is the least disturbed.
"""

import argparse
import atexit
import bisect
import collections
import ctypes
import hashlib
import json
import os
import re
import shutil
import signal
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROUNDS = 9
# The micro-benchmarks', each a fraction of a second: more rounds, so a
# runner's passing load spoils none of the best of them.
MICRO_ROUNDS = 21

REPO = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../.."))

# The C project built: Lua 5.4.7's source.
LUA = (
    [
        "https://www.lua.org/ftp/lua-5.4.7.tar.gz",
        "https://www.tecgraf.puc-rio.br/lua/ftp/lua-5.4.7.tar.gz",
    ],
    "9fbf5e28ef86c69858f6d3d34eccc32e911c1a28b4120ff3e84aaa70cfbf1e30",
)


def fetch(urls, sha256, cache):
    """The file at the first of `urls` (one URL, or a list of mirrors) that
    serves it, into `cache`, checked against `sha256`."""
    urls = [urls] if isinstance(urls, str) else urls
    url = urls[0]
    path = os.path.join(cache, os.path.basename(url))
    if not os.path.exists(path):
        os.makedirs(cache, exist_ok=True)
        for u in urls:
            r = subprocess.run(
                ["curl", "-sSfL", "--retry", "5", "--retry-all-errors", "-o", path + ".part", u]
            )
            if r.returncode == 0:
                url = u
                break
        else:
            sys.exit(f"could not fetch {urls}")
        os.replace(path + ".part", path)
    with open(path, "rb") as f:
        got = hashlib.sha256(f.read()).hexdigest()
    if got != sha256:
        os.unlink(path)
        sys.exit(f"{url}: SHA-256 {got}, not {sha256}")
    return path


def alpine_root(manifest, cache):
    """The root filesystem `manifest` (under guests/alpine/fetch) lists,
    unpacked in order into `cache`, as the end-to-end tests make theirs."""
    lines = open(os.path.join(REPO, "guests/alpine/fetch", manifest + ".txt")).read()
    root = os.path.join(cache, "alpine-root-" + manifest)
    done = os.path.join(root, ".fwe-complete")
    if os.path.exists(done) and open(done).read() == lines:
        return root
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(root)
    for line in lines.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        path, sha256 = line.split()
        f = fetch("https://dl-cdn.alpinelinux.org/alpine/" + path, sha256, cache)
        excludes = [".PKGINFO", ".SIGN.*", ".pre-*", ".post-*", ".trigger"]
        args = [x for e in excludes for x in ("--exclude", e)]
        # `-p`: the modes as the archive has them (`/tmp`'s 1777), not
        # narrowed by the umask.
        subprocess.run(["tar", "--xattrs", "-xpzf", f] + args + ["-C", root], check=True)
    with open(done, "w") as f:
        f.write(lines)
    return root

# name, arguments to bench, unit
MICRO = [
    ("getpid", ["getpid", "200000"], "ns"),
    ("getppid", ["syscall", "200000"], "ns"),
    # Calls made by 3 threads at once (the macOS runners have 3 cores): the
    # time per call of each, the same as one thread's when they run side
    # by side.
    ("getppid, 3 threads", ["par", "getppid", "3", "100000"], "ns"),
    ("fstat, 3 threads", ["par", "fstat", "3", "100000"], "ns"),
    ("thread create+join", ["thread", "2000"], "us"),
    ("fork+exit+wait", ["fork", "200"], "us"),
    # The calls programs at work make most (a database's reads, a
    # repository's lookups, an allocator's mappings).
    ("pread 4 KiB", ["file", "pread", "100000"], "ns"),
    ("stat", ["file", "stat", "100000"], "ns"),
    ("open+close", ["file", "open", "50000"], "ns"),
    ("mmap+munmap", ["file", "mmap", "50000"], "ns"),
    # A fault the program's own handler steps past (a JIT's implicit null
    # check), there and back.
    ("SIGSEGV handled", ["fault", "50000"], "us"),
    # Code made at run time (fwe runs it by translation, macOS as it is):
    # the same machine code each way, at work and as it is made.
    ("JIT code: calls and returns", ["jit", "calls", "200"], "ns"),
    ("JIT code: a switch through br", ["jit", "indirect", "500000"], "ns"),
    ("JIT code: calls through a register", ["jit", "pointers", "5000000"], "ns"),
    ("JIT code: a loop", ["jit", "loop", "10000000"], "ns"),
    ("JIT code: 4096 functions in turn", ["jit", "functions", "2000000"], "ns"),
    ("JIT code: a function made and run", ["jit", "made", "2000"], "us"),
    # A graphical program's traffic with its X server ([`x_server`]): a
    # request waited for, and a window's frame drawn through shared memory.
    ("X request round trip", ["x11", "rtt", "20000"], "us"),
    ("X frame through shared memory", ["x11", "shm", "300"], "us"),
]


# How many times native macOS's figure fwe's may be, on the same runner
# (PLAN.md, "Native speed"): system calls 1.5x, the process and thread
# calls and start-up 3x.
BUDGETS = {
    "startup (ms)": 3.0,
    "getpid (ns)": 1.5,
    "getppid (ns)": 1.5,
    "getppid, 3 threads (ns)": 1.5,
    "fstat, 3 threads (ns)": 1.5,
    "pread 4 KiB (ns)": 1.5,
    "stat (ns)": 1.5,
    "open+close (ns)": 1.5,
    "mmap+munmap (ns)": 1.5,
    "thread create+join (us)": 3.0,
    "fork+exit+wait (us)": 3.0,
    "fork+exec+wait (us)": 3.0,
    # Programs at work that are mostly system calls (a database on disk, a
    # repository), as a call is.
    "SQLite (s)": 1.5,
    "git (s)": 1.5,
    # JIT runtimes at work (OpenJDK compiling, then running, a
    # multi-threaded application; Node.js and LuaJIT running a script),
    # against the same releases built for macOS.
    "JDK (s)": 1.5,
    "Node.js (s)": 1.5,
    "LuaJIT (s)": 1.5,
    # Code made at run time at work, against the same code run from the
    # program's file (the same machine code, natively).
    "JIT code: calls and returns (ns)": 1.3,
    "JIT code: a switch through br (ns)": 1.3,
    "JIT code: calls through a register (ns)": 1.3,
    "JIT code: a loop (ns)": 1.3,
    # A graphical program's calls to its X server, as a system call is.
    "X request round trip (us)": 1.5,
    "X frame through shared memory (us)": 1.5,
}

# The most fwe's figure may be, in the row's own unit: making a
# translation, which running code natively has no counterpart of (a
# function made and run: the block made for it, placed and linked).
LIMITS = {
    "JIT code: a function made and run (us)": 2.0,
}

# How much longer than its own code fwe may make a program that computes
# take: its share ([`pcs`]), all of a run's samples over those in the
# program's own code. Its time against macOS's stays in the table, but
# that also measures the builds' differences (Alpine's compiler and C
# library against Homebrew's), not only fwe.
SHARE = "fwe's share"
# Which of fwe's backends ran each benchmark's programs ([`backends`]).
BACKEND = "fwe's backend"
# The results of the same benchmarks in a Linux VM on the same Mac
# (tools/bench/vm.sh): what fwe competes with.
VM = "Linux VM"
# The same benchmarks under fwe with its VM backend (`fwe --vm`, vm.sh).
FWE_VM = "fwe VM"
SHARE_BUDGETS = {
    # A C build's, by one compile of it (one process; its starts and forks
    # keep their own budgets above).
    "build Lua (s)": 1.2,
    "Lua script (s)": 1.2,
    "Python script (s)": 1.2,
    "xz (s)": 1.2,
}

# The workloads (tools/bench/workloads).
WORKLOADS = os.path.join(REPO, "tools/bench/workloads")

# Homebrew's builds the native side runs, under `--brew`: the clang release
# Alpine's root has, and the programs of the workloads.
BREW = {
    "clang": "opt/llvm@22/bin/clang",
    "python": "opt/python@3.14/bin/python3.14",
    "sqlite": "opt/sqlite/bin/sqlite3",
    "git": "opt/git/bin/git",
    "xz": "opt/xz/bin/xz",
    "jdk": "opt/openjdk@25/bin",
    "node": "opt/node@24/bin/node",
    "luajit": "opt/luajit/bin/luajit",
}



def backends(cmd, fresh=()):
    """Which of fwe's backends ran the programs of `cmd` (fwe, or `env -i`
    and fwe), by the `backend:` marks of `FWE_TIMING` (every program a run
    starts, in every process): "native", "VM", or both with how many of
    each. `fresh` is emptied first."""
    for d in fresh:
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
    if cmd[0] == "env":
        cmd, env = cmd[:2] + ["FWE_TIMING=1"] + cmd[2:], None
    else:
        env = dict(os.environ, FWE_TIMING="1")
    r = subprocess.run(cmd, env=env, capture_output=True, text=True, errors="replace")
    n = collections.Counter(re.findall(r"timing: backend: (native|vm) ", r.stderr))
    if not n:
        return "unknown"
    if len(n) == 1:
        return "native" if "native" in n else "VM"
    return f"native {n['native']}, VM {n['vm']}"


def x_server(xvfb):
    """A headless X server (`xvfb`, an Xvfb) for the X benchmarks, at a
    display of its own on its Unix socket only: `DISPLAY` names it to every
    program run here. Stopped when this ends."""
    n = 57
    p = subprocess.Popen([xvfb, f":{n}", "-screen", "0", "1024x768x24", "-nolisten", "tcp"],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    atexit.register(lambda: (p.terminate(), p.wait()))
    deadline = time.monotonic() + 30
    while not os.path.exists(f"/tmp/.X11-unix/X{n}"):
        if p.poll() is not None or time.monotonic() > deadline:
            sys.exit(f"{xvfb} :{n} did not start")
        time.sleep(0.1)
    os.environ["DISPLAY"] = f":{n}"


GEARS = "glxgears frame (ms)"
# Mesa's software renderer, on one thread: the runners' cores differ.
GEARS_ENV = {"LIBGL_ALWAYS_SOFTWARE": "1", "GALLIUM_DRIVER": "llvmpipe", "LP_NUM_THREADS": "1"}


# The display glxgears draws on: Alpine's Xvfb, an X server with GLX
# (Homebrew's has none), beside it in its root or container.
GEARS_DISPLAY = 9
GEARS_CMD = f"DISPLAY=:{GEARS_DISPLAY} exec /usr/bin/glxgears -geometry 300x300+0+0"


def gears_ms(cmd, env=None):
    """glxgears' time per frame as `cmd` runs it: it reports its frames
    every 5 seconds; the second report, the first's taking its start
    too."""
    err = tempfile.TemporaryFile()
    p = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=err, text=True)
    timer = threading.Timer(120, p.kill)
    timer.start()
    rates = []
    try:
        for line in p.stdout:
            m = re.search(r"= ([0-9.]+) FPS", line)
            if m:
                rates.append(float(m.group(1)))
            if len(rates) == 2:
                break
    finally:
        timer.cancel()
        p.kill()
        p.wait()
    if len(rates) < 2 or rates[1] <= 0:
        err.seek(0)
        said = err.read().decode(errors="replace")[-4000:]
        sys.exit(f"glxgears gave no frame rate: {rates}, exit {p.returncode}; it said:\n{said}")
    return 1000.0 / rates[1]


def gears_fwe(a, fwe, guest_env):
    """glxgears under fwe, on Alpine's Xvfb run by fwe in the same root (a
    display of the root's own); against the same two programs in a Linux
    container, there being no macOS build of them."""
    root = alpine_root("display", a.cache)
    in_root = guest_env + fwe + ["--root", root]
    x11 = os.path.join(root, "tmp/.X11-unix")
    os.makedirs(x11, exist_ok=True)
    os.chmod(x11, 0o1777)
    # The X server's fonts' indexes, as their package's trigger makes them.
    for prog in ("mkfontscale", "mkfontdir"):
        subprocess.run(in_root + [os.path.join(root, "usr/bin", prog), "/usr/share/fonts/misc"],
                       check=True, capture_output=True)
    sock = os.path.join(x11, f"X{GEARS_DISPLAY}")
    for stale in (sock, os.path.join(root, f"tmp/.X{GEARS_DISPLAY}-lock")):
        if os.path.lexists(stale):
            os.remove(stale)
    err = tempfile.TemporaryFile()
    xvfb = subprocess.Popen(
        in_root + [os.path.join(root, "usr/bin/Xvfb"), f":{GEARS_DISPLAY}",
                   "-screen", "0", "1024x768x24", "-nolisten", "tcp"],
        stdout=subprocess.DEVNULL, stderr=err)
    try:
        deadline = time.monotonic() + 120
        while not os.path.exists(sock):
            if xvfb.poll() is not None or time.monotonic() > deadline:
                err.seek(0)
                sys.exit("Xvfb under fwe did not start: " + err.read().decode(errors="replace")[-4000:])
            time.sleep(0.2)
        return gears_ms(guest_env + [f"{k}={v}" for k, v in GEARS_ENV.items()] + fwe
                        + ["--root", root, os.path.join(root, "bin/sh"), "-c", GEARS_CMD])
    finally:
        xvfb.kill()
        xvfb.wait()


def best(f, rounds=ROUNDS):
    return min(f() for _ in range(rounds))


def run_bench(prefix, bench, args):
    out = subprocess.run(prefix + [bench] + args, check=True, capture_output=True, text=True)
    return float(out.stdout.split()[-1])


def startup_ms(cmd, n=30):
    def once():
        start = time.perf_counter()
        for _ in range(n):
            subprocess.run(cmd, check=True)
        return (time.perf_counter() - start) / n * 1e3

    return best(once)


def micro(prefix, bench):
    """The micro-benchmarks, with `prefix` (fwe and its options, or none)."""
    r = {"startup (ms)": startup_ms(prefix + [bench, "exit"])}
    for name, args, unit in MICRO:
        r[f"{name} ({unit})"] = best(lambda: run_bench(prefix, bench, args))
    # fork + exec of the benchmark itself (under fwe without a root, the
    # guest sees host paths).
    r["fork+exec+wait (us)"] = best(lambda: run_bench(prefix, bench, ["forkexec", "100", bench]))
    return r


def micro_pair(fwe, guest, native):
    """The micro-benchmarks under fwe (`fwe` its command, `guest` the Linux
    build) and natively (`native`), their rounds taken in turn: a runner's
    load comes and goes, and so it falls on both alike."""
    def pair(f, g, rounds=MICRO_ROUNDS):
        a, b = [], []
        for _ in range(rounds):
            a.append(f())
            b.append(g())
        return min(a), min(b)

    runs = [("startup (ms)", lambda p, b: startup_ms_once(p + [b, "exit"]))]
    for name, args, unit in MICRO:
        runs.append((f"{name} ({unit})", lambda p, b, args=args: run_bench(p, b, args)))
    # fork + exec of the benchmark itself (under fwe without a root, the
    # guest sees host paths).
    runs.append(
        ("fork+exec+wait (us)", lambda p, b: run_bench(p, b, ["forkexec", "100", b]))
    )
    ours, theirs = {}, {}
    for name, f in runs:
        ours[name], theirs[name] = pair(lambda: f(fwe, guest), lambda: f([], native))
    return ours, theirs


def startup_ms_once(cmd, n=30):
    start = time.perf_counter()
    for _ in range(n):
        subprocess.run(cmd, check=True)
    return (time.perf_counter() - start) / n * 1e3


def unpack_lua(tarball, into):
    subprocess.run(["tar", "-xzf", tarball, "-C", into], check=True)
    return os.path.join(into, "lua-5.4.7")


def checked(cmd, retrace=None):
    """Run `cmd`; on failure, show the end of its output and, with
    `retrace` (the command made to trace itself), run it once more that
    way, then stop."""
    r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    if r.returncode == 0:
        return
    print(f"failed ({r.returncode}): {' '.join(cmd)}", file=sys.stderr)
    print((r.stdout + r.stderr)[-4000:], file=sys.stderr)
    if retrace:
        subprocess.run(retrace(cmd), capture_output=True)
        print("traced", file=sys.stderr)
    sys.exit(1)


def lua_build_s(cmd_for, src, retrace=None):
    """Seconds to build Lua from clean with `cmd_for(make_args)`, best of
    three."""
    # Alpine's clang, in the container.
    return best(lambda: lua_build_once(cmd_for, "clang", retrace), 3)


def lua_build_once(cmd_for, cc, retrace=None):
    """Seconds to build Lua from clean once with `cmd_for(make_args)`, with
    compiler `cc`."""
    checked(cmd_for(["clean"]))
    start = time.perf_counter()
    checked(cmd_for(["-j4", "posix", f"CC={cc}"]), retrace)
    return time.perf_counter() - start


def linux(a):
    x_server(a.xvfb)
    r = micro([], a.bench)
    lua = fetch(*LUA, a.cache)
    with tempfile.TemporaryDirectory() as d:
        src = unpack_lua(lua, d)
        image = "alpine:3.24"
        subprocess.run(["docker", "pull", "-q", image], check=True, capture_output=True)
        # The toolchain installed once, in a container kept for the builds.
        name = f"fwe-bench-{os.getpid()}"
        subprocess.run(
            ["docker", "run", "-d", "--name", name, "-v", f"{src}:/src", image, "sleep", "3600"],
            check=True,
            capture_output=True,
        )
        try:
            subprocess.run(
                ["docker", "exec", name, "apk", "add", "-q", "clang22", "gcc", "make", "musl-dev"],
                check=True,
            )
            r["build Lua (s)"] = lua_build_s(
                lambda args: ["docker", "exec", "-w", "/src", name, "make"] + args, src
            )
            # The workloads, with the Lua just built and Alpine's programs.
            shutil.copytree(WORKLOADS, os.path.join(src, "wl"))
            subprocess.run(
                ["docker", "exec", name, "apk", "add", "-q", "sqlite", "git", "xz", "python3"],
                check=True,
            )

            def timed(cmd):
                full = ["docker", "exec", name, "sh", "-c", f"rm -rf /tmp/w && mkdir /tmp/w && cd /tmp/w && {cmd}"]
                start = time.perf_counter()
                subprocess.run(full, check=True, capture_output=True)
                return time.perf_counter() - start

            # glxgears and Xvfb, Alpine's, in a container of their own,
            # removed after (killing `docker run` leaves it running).
            env = [x for k, v in GEARS_ENV.items() for x in ("-e", f"{k}={v}")]
            sock = f"/tmp/.X11-unix/X{GEARS_DISPLAY}"
            try:
                r[GEARS] = gears_ms(
                    ["docker", "run", "--rm", "--name", "fwe-gears"] + env + [image, "sh", "-c",
                     "apk add -q xvfb font-misc-misc mesa-utils mesa-dri-gallium"
                     f" && (Xvfb :{GEARS_DISPLAY} -screen 0 1024x768x24 -nolisten tcp"
                     " >/dev/null 2>&1 &)"
                     f" && while [ ! -e {sock} ]; do sleep 0.1; done && {GEARS_CMD}"]
                )
            finally:
                subprocess.run(["docker", "rm", "-f", "fwe-gears"], capture_output=True)
            for row, cmd in (
                ("Lua script (s)", "/src/src/lua /src/wl/bench.lua"),
                ("Python script (s)", "python3 /src/wl/bench.py"),
                ("SQLite (s)", "sqlite3 /tmp/w/db '.read /src/wl/bench.sql'"),
                ("git (s)", "sh /src/wl/git.sh /src/src /usr/bin/git"),
                ("xz (s)", "sh /src/wl/xz.sh /src/src /usr/bin/xz"),
            ):
                r[row] = best(lambda cmd=cmd: timed(cmd), 3)
        finally:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    write(a.out, r)


def macos(a):
    x_server(a.xvfb)
    fwe = [a.fwe]
    # Where a start's time goes (FWE_TIMING), for the log.
    for args in (["exit"], ["forkexec", "2", a.bench]):
        env = dict(os.environ, FWE_TIMING="1")
        r = subprocess.run(fwe + [a.bench] + args, env=env, capture_output=True, text=True)
        print(r.stderr, file=sys.stderr)
    ours, theirs = micro_pair(fwe, a.bench, a.native)
    # Where the file calls' time goes under fwe, for the log.
    for name, args, _ in MICRO:
        if args[0] == "file":
            sampled(f"{name} (micro)", fwe + [a.bench, "file", args[1], "3000000"])
            pcs(f"{name} (micro)", fwe + [a.bench, "file", args[1], "300000"])
    # And a fork's: its steps in fwe, the host's calls and the kernel's
    # work in both processes, under fwe and natively.
    phases("fork+exit+wait (micro)", fwe + [a.bench, "fork", "300"])
    faulted("fork+exit+wait (micro)", fwe + [a.bench, "fork", "300"])
    pcs("fork+exit+wait (micro)", fwe + [a.bench, "fork", "2000"])
    pcs("fork+exit+wait (micro) natively", [a.native, "fork", "2000"],
        execname=os.path.basename(a.native)[:16])
    results = {"fwe": ours, "macOS": theirs}
    # The benchmark program alone, and forking and running itself.
    ran = backends(fwe + [a.bench, "forkexec", "2", a.bench])
    results[BACKEND] = {row: ran for row in ours}
    if not a.no_build:
        build(a, fwe, results)
    if a.linux:
        with open(a.linux) as f:
            results["Linux"] = json.load(f)
    if a.linux_vm:
        with open(a.linux_vm) as f:
            results[VM] = json.load(f)
    if a.fwe_vm:
        with open(a.fwe_vm) as f:
            results[FWE_VM] = json.load(f)["fwe"]
    write(a.out, results)
    table = render(results)
    over = over_budget(results)
    if over:
        table += "\n\nOver budget: " + ", ".join(over)
    print(table)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as f:
            f.write(table + "\n")
    if over:
        sys.exit("over budget: " + ", ".join(over))


def over_budget(results):
    """The benchmarks whose fwe / macOS ratio exceeds its budget, whose
    figure exceeds its limit, or whose share of fwe's exceeds its share
    budget. A missing figure is one: the budget is not shown to hold."""
    over = []
    shares = results.get(SHARE, {})
    for row, budget in SHARE_BUDGETS.items():
        if row not in results["fwe"]:
            continue
        share = shares.get(row)
        if share is None:
            over.append(f"{row}: no share of fwe's")
        elif share > budget:
            over.append(f"{row} fwe's share {share:.2f}x > {budget}x")
    for row, budget in BUDGETS.items():
        fwe, mac = results["fwe"].get(row), results["macOS"].get(row)
        if fwe is None:
            continue
        if not mac:
            over.append(f"{row}: no macOS figure")
        elif fwe / mac > budget:
            over.append(f"{row} {fwe / mac:.1f}x > {budget}x")
    for row, limit in LIMITS.items():
        fwe = results["fwe"].get(row)
        if fwe is not None and fwe > limit:
            over.append(f"{row} {fwe:.2f} > {limit}")
    return over


def build(a, fwe, results):
    """Lua built with clang under fwe, in an Alpine root's /tmp (the guest
    given only its own environment), and natively with Homebrew's clang of
    the same release, so the two differ by fwe, not by the compiler
    (Apple's clang is another, faster build of it). Then the workloads,
    the Lua script with the Lua each side built."""
    lua = fetch(*LUA, a.cache)
    root = alpine_root("clang", a.cache)
    tmp = os.path.join(root, "tmp")
    os.makedirs(tmp, exist_ok=True)
    shutil.rmtree(os.path.join(tmp, "lua-5.4.7"), ignore_errors=True)
    src = unpack_lua(lua, tmp)
    guest_env = ["env", "-i", "PATH=/usr/bin:/bin", "HOME=/root"]
    make = guest_env + fwe + ["--root", root, os.path.join(root, "usr/bin/make")]
    make += ["-C", "/tmp/lua-5.4.7"]
    trace = os.path.abspath("bench-trace.txt")
    i = len(guest_env) + 1  # after fwe itself

    def traced(cmd):
        # The compiler alone, its messages and fwe's shown, then the build.
        alone = guest_env + fwe + ["--strace", "--root", root, os.path.join(root, "usr/bin/clang")]
        r = subprocess.run(alone + ["--version"], capture_output=True, text=True, errors="replace")
        with open("bench-clang.txt", "w") as f:
            f.write(r.stdout + r.stderr)
        print(f"clang --version: {r.returncode}\n{(r.stdout + r.stderr)[-6000:]}", file=sys.stderr)
        return cmd[:i] + ["--strace", f"--strace-file={trace}"] + cmd[i:]

    native = tempfile.mkdtemp()
    native_src = unpack_lua(lua, native)
    # Each round under fwe, then natively, three times: the runner's load
    # falls on both alike.
    ours, theirs = [], []
    for _ in range(3):
        # Alpine's clang, in its root under fwe.
        ours.append(lua_build_once(lambda args: make + args, "clang", traced))
        theirs.append(
            lua_build_once(
                lambda args: ["make", "-C", native_src] + args,
                os.path.join(a.brew, BREW["clang"]),
            )
        )
    results["fwe"]["build Lua (s)"] = min(ours)
    checked(make + ["clean"])
    results.setdefault(BACKEND, {})["build Lua (s)"] = backends(
        make + ["-j4", "posix", "CC=clang"])
    results["macOS"]["build Lua (s)"] = min(theirs)
    # Where one compile's time goes: fwe's marks (start-up, the code pages
    # written as they first ran), and what it and the native one cost the
    # host.
    one = ["-O2", "-c", "-o", "/tmp/one.o", "/tmp/lua-5.4.7/src/lvm.c"]
    clang = guest_env + fwe + ["--root", root, os.path.join(root, "usr/bin/clang")] + one
    timed = clang[:2] + ["FWE_TIMING=1"] + clang[2:]
    r = subprocess.run(timed, capture_output=True, text=True, errors="replace")
    marks = [l.split("timing: ", 1)[1] for l in r.stderr.splitlines() if "timing: " in l]
    print("clang -c lvm.c: fwe's marks: " + "; ".join(marks), file=sys.stderr)
    native_one = [os.path.join(a.brew, BREW["clang"]), "-O2", "-c", "-o",
                  os.path.join(native, "one.o"), os.path.join(native_src, "src/lvm.c")]
    rusage("clang -c lvm.c", "fwe", clang, ())
    rusage("clang -c lvm.c", "macOS", native_one, ())
    sampled("clang -c lvm.c", clang)
    # fwe's share of one compile: the build's budget.
    mine = pcs("clang -c lvm.c", clang, True)
    if mine:
        results.setdefault(SHARE, {})["build Lua (s)"] = mine[1] / max(mine[0], 1)
    # Its memory as it compiles, by kind of region.
    proc = subprocess.Popen(clang, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.25)
    v = subprocess.run(["vmmap", "-summary", str(proc.pid)], capture_output=True, text=True,
                       errors="replace").stdout
    proc.wait()
    table = v[v.find("REGION TYPE"):v.find("TOTAL, minus")]
    print("clang -c lvm.c under fwe, its memory:\n" + table, file=sys.stderr)
    # Its system calls, and how much memory it maps and unmaps.
    trace = os.path.abspath("bench-clang-one.trace")
    subprocess.run(clang[:i] + ["--strace", f"--strace-file={trace}"] + clang[i:],
                   capture_output=True)
    calls = collections.Counter()
    sizes = collections.Counter()
    with open(trace, errors="replace") as f:
        for line in f:
            m = re.search(r"\] ([a-z_0-9]+)\(([^,)]*)(?:, ([^,)]*))?", line)
            if m:
                calls[m.group(1)] += 1
                if m.group(1) in ("mmap", "munmap") and m.group(3):
                    sizes[m.group(1)] += int(m.group(3), 16)
    top = ", ".join(f"{c} {n}" for n, c in calls.most_common(12))
    mib = {k: v >> 20 for k, v in sizes.items()}
    print(f"clang -c lvm.c: {sum(calls.values())} system calls: {top}; MiB {mib}", file=sys.stderr)
    # The Lua it built runs.
    out = subprocess.run(
        fwe + ["--root", root, os.path.join(src, "src/lua"), "-e", "print(6*7)"],
        check=True,
        capture_output=True,
        text=True,
    )
    if out.stdout.strip() != "42":
        sys.exit(f"the Lua fwe built printed {out.stdout!r}")
    # The Lua script, in the build's root.
    shutil.copytree(WORKLOADS, os.path.join(tmp, "wl"), dirs_exist_ok=True)
    workload(
        results,
        "Lua script (s)",
        guest_env + fwe + ["--root", root, os.path.join(src, "src/lua"), "/tmp/wl/bench.lua"],
        [os.path.join(native_src, "src/lua"), os.path.join(WORKLOADS, "bench.lua")],
        (),
        len(guest_env) + 1,
        profiled=True,
        share=True,
    )
    workloads(a, fwe, guest_env, os.path.join(native_src, "src"), results)
    results["fwe"][GEARS] = gears_fwe(a, fwe, guest_env)
    jdk(a, fwe, guest_env, results)
    host_costs()
    for name, manifest, program, script in [("Node.js", "nodejs", "/usr/bin/node", "bench.js"),
                                            ("LuaJIT", "luajit", "/usr/bin/luajit", "bench.lua")]:
        jit_runtime(a, fwe, guest_env, results, name, manifest, program, script)
    shutil.rmtree(native, ignore_errors=True)


def host_costs():
    """What the host's work behind a translator costs, natively
    (tools/bench/host.c): a fault, a fetch from a page that is not
    executable (as native code's jump into a JIT's code reaches fwe) and a
    read of a page with no access, and the lines the kernel logged for the
    process meanwhile; and code made ready to run after it is written, a
    cache line at a time."""
    d = tempfile.mkdtemp()
    exe = os.path.join(d, "host")
    subprocess.run(["cc", "-O2", "-o", exe, os.path.join(os.path.dirname(__file__), "host.c")],
                   check=True)
    p = subprocess.Popen([exe, "20000"], stdout=subprocess.PIPE, text=True)
    fetch, read, dc, ic, sys_call = p.communicate()[0].split()
    logged = subprocess.run(["log", "show", "--last", "5m", "--style", "compact", "--predicate",
                             f"processID == {p.pid} AND sender == \"kernel\""],
                            capture_output=True, text=True, errors="replace").stdout.splitlines()
    logged = [l for l in logged if str(p.pid) in l]
    print(f"The host's faults: a fetch from a page not executable {fetch} us, a read of a page "
          f"with no access {read} us; the kernel logged {len(logged)} lines for them"
          + (f", the first: {logged[0]}" if logged else ""), file=sys.stderr)
    print(f"The host's code made ready to run, a cache line: dc cvau {dc} ns, ic ivau {ic} ns, "
          f"sys_icache_invalidate {sys_call} ns", file=sys.stderr)
    shutil.rmtree(d, ignore_errors=True)


def jit_runtime(a, fwe, guest_env, results, name, manifest, program, script):
    """A JIT runtime at work: `program` of Alpine's root `manifest` running
    `script` (tools/bench/workloads) under fwe, and Homebrew's build of the
    same release natively (BREW, by the program's name). Then where its
    time goes under fwe, by program counter, translated code named by the
    code cache's map; and the translator's counts, the script run three
    times into one directory of the blocks made (`FWE_JIT_SEEN`): how many
    each run made that an earlier one had, of a file's code and generated,
    the third making none that two earlier made at the same address from
    the same words (it takes them, kept); then once with its blocks
    counting their runs (`FWE_JIT_COUNT`)."""
    root = alpine_root(manifest, a.cache)
    shutil.copytree(WORKLOADS, os.path.join(root, "tmp/wl"), dirs_exist_ok=True)
    ours = guest_env + fwe + ["--root", root, os.path.join(root, program.lstrip("/")),
                              f"/tmp/wl/{script}"]
    theirs = [os.path.join(a.brew, BREW[os.path.basename(program)]),
              os.path.join(WORKLOADS, script)]
    workload(results, f"{name} (s)", ours, theirs, (), len(guest_env) + 1)
    jit_map = tempfile.mkdtemp()
    pcs(name, guest_env + [f"FWE_JIT_MAP={jit_map}"] + ours[len(guest_env):], jit_map=jit_map)
    shutil.rmtree(jit_map, ignore_errors=True)
    pcs(f"{name} natively", theirs, execname=os.path.basename(program))
    seen = tempfile.mkdtemp()
    for label, extra in [("", [f"FWE_JIT_SEEN={seen}"]), (" again", [f"FWE_JIT_SEEN={seen}"]),
                         (" a third time", [f"FWE_JIT_SEEN={seen}"]),
                         (" with its blocks counting", ["FWE_JIT_COUNT=1"])]:
        r = run_limited(guest_env + ["FWE_TIMING=1"] + extra + ours[len(guest_env):],
                        f"{name}{label}")
        said = [line.split("timing: ", 1)[1] for line in r.stderr.splitlines()
                if "timing: exit" in line and ("JIT code: " in line or "system calls" in line)]
        print(f"{name}{label}, fwe's marks (exit {r.returncode}): " + " | ".join(said),
              file=sys.stderr)
        if label == " a third time":
            # Blocks of generated code two earlier runs made at the same
            # address from the same words, made again: none (taken, kept).
            twice = [int(m.group(1)) for m in
                     (re.search(r"made before by another process: .*?; generated \d+ \((\d+)\)",
                                s) for s in said) if m]
            if not twice:
                sys.exit(f"{name}: no count of blocks made before in {said!r}")
            if sum(twice) != 0:
                sys.exit(f"{name}: {sum(twice)} blocks of generated code two earlier runs "
                         f"made, made again rather than taken: {said!r}")
    shutil.rmtree(seen, ignore_errors=True)


# The most seconds one run of a workload may take: a run that hangs fails
# the benchmarks with where it is, rather than the job's time limit with
# nothing.
LIMIT = 300


def run_limited(cmd, name):
    """`cmd` run as `subprocess.run` with its output captured as text, for
    at most LIMIT seconds. Past them, each of its processes is sampled
    (`bench-<name>-hung-<pid>.sample`, uploaded with the results; what is
    on top of its threads' stacks printed), the process group it was started
    in is stopped, and the benchmarks fail."""
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                         errors="replace", start_new_session=True)
    try:
        out, err = p.communicate(timeout=LIMIT)
    except subprocess.TimeoutExpired:
        slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
        pids, todo = [], [p.pid]
        while todo:
            pid = todo.pop()
            pids.append(pid)
            kids = subprocess.run(["pgrep", "-P", str(pid)], capture_output=True, text=True)
            todo += [int(k) for k in kids.stdout.split()]
        for pid in pids:
            path = os.path.abspath(f"bench-{slug}-hung-{pid}.sample")
            subprocess.run(["sample", str(pid), "3", "-file", path], capture_output=True)
            try:
                with open(path, errors="replace") as f:
                    text = f.read()
            except OSError:
                continue
            top = text.split("Sort by top of stack", 1)[-1].split("\n\n", 1)[0].splitlines()[1:25]
            print(f"{name}: process {pid} after {LIMIT} s, on top of its stacks:\n"
                  + "\n".join(top), file=sys.stderr)
        os.killpg(p.pid, signal.SIGKILL)
        out, err = p.communicate()
        sys.exit(f"{name}: still running after {LIMIT} s: {cmd}\nits error output's end: "
                 f"{err[-3000:]}")
    return subprocess.CompletedProcess(cmd, p.returncode, out, err)


def workload(results, name, ours, theirs, fresh, at, profiled=False, share=False):
    """Time workload `name`: command `ours` under fwe and `theirs` natively,
    in turns, three rounds, the best of each kept. Each round starts with
    the directories `fresh` empty. Both must succeed and print the same.
    Then `ours` once more, traced (fwe's options go in at `at`, after fwe
    itself), its system calls counted in the log: where fwe's time goes;
    and, `profiled` (a program in one process), once more sampled, its
    share of fwe's kept with `share` ([`pcs`])."""
    times = {"fwe": [], "macOS": []}
    outs = {}
    for _ in range(3):
        for side, cmd in (("fwe", ours), ("macOS", theirs)):
            for d in fresh:
                shutil.rmtree(d, ignore_errors=True)
                os.makedirs(d)
            start = time.perf_counter()
            r = run_limited(cmd, f"{name} {side}")
            times[side].append(time.perf_counter() - start)
            if r.returncode != 0:
                # The head of the output holds a crash report's summary (a
                # JVM's), its end what led to the failure.
                out = r.stdout if len(r.stdout) <= 12000 else (
                    f"{r.stdout[:6000]}\n[...]\n{r.stdout[-6000:]}")
                sys.exit(f"{name} {side} failed ({r.returncode}): {r.stderr[-3000:]}\n"
                         f"its output: {out}")
            outs[side] = r.stdout
    if outs["fwe"] != outs["macOS"]:
        sys.exit(f"{name}: fwe printed {outs['fwe']!r}, macOS {outs['macOS']!r}")
    for side in times:
        results[side][name] = min(times[side])
    for d in fresh:
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
    trace = os.path.abspath(f"bench-{name.split()[0].lower()}.trace")
    run_limited(ours[:at] + ["--strace", f"--strace-file={trace}"] + ours[at:], f"{name} traced")
    calls = collections.Counter()
    with open(trace, errors="replace") as f:
        for line in f:
            m = re.search(r"\] ([a-z_0-9]+)\(", line)
            if m:
                calls[m.group(1)] += 1
    top = ", ".join(f"{c} {n}" for c, n in ((n, c) for c, n in calls.most_common(14)))
    print(f"{name}: {sum(calls.values())} system calls under fwe: {top}", file=sys.stderr)
    results.setdefault(BACKEND, {})[name] = backends(ours, fresh)
    if profiled:
        mine = profile(name, ours, theirs, fresh, share)
        if mine:
            results.setdefault(SHARE, {})[name] = mine[1] / max(mine[0], 1)


def git_commands(ours, theirs, fresh, root):
    """Where the git workload's time goes, by git command, on both sides:
    each git process's run time (`t_abs` at its exit, git's own clock) as
    git's trace2 event log records it, summed by command."""
    guest_log = "/tmp/git-trace2.json"
    logs = {"fwe": os.path.join(root, guest_log.lstrip("/")),
            "macOS": os.path.abspath("bench-git-trace2.json")}
    runs = {"fwe": ours[:2] + [f"GIT_TRACE2_EVENT={guest_log}"] + ours[2:],
            "macOS": ["env", f"GIT_TRACE2_EVENT={logs['macOS']}"] + theirs}
    for side, cmd in runs.items():
        for d in fresh:
            shutil.rmtree(d, ignore_errors=True)
            os.makedirs(d)
        if os.path.exists(logs[side]):
            os.remove(logs[side])
        subprocess.run(cmd, capture_output=True)
        names, took = {}, collections.Counter()
        count = collections.Counter()
        with open(logs[side], errors="replace") as f:
            for line in f:
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                if ev.get("event") == "cmd_name":
                    names[ev["sid"]] = ev["name"]
                elif ev.get("event") == "exit":
                    n = names.get(ev["sid"], "?")
                    took[n] += ev["t_abs"]
                    count[n] += 1
        top = ", ".join(f"{n} {count[n]}x {t * 1e3:.0f} ms" for n, t in took.most_common(10))
        print(f"git (s) {side}, by command: {sum(took.values()) * 1e3:.0f} ms in git: {top}",
              file=sys.stderr)


# A process's regions, as `vmmap` lists them but in milliseconds, not the
# half second `vmmap` takes (longer than some of the programs measured
# run): `proc_pidinfo`'s `PROC_PIDREGIONPATHINFO`, a `struct
# proc_regionwithpathinfo` (the protection at 0, the user tag at 32, the
# address and size at 80, the file's path at 248).
REGION_INFO = 8
REGION_SIZE = 96 + 152 + 1024
# The user tags of the host's shared library cache, one region in the
# listing (`VM_MEMORY_SHARED_PMAP`), and of fwe's stubs (`STUB_TAG` in
# crates/native/src/prepare.rs, "Memory Tag 241" in `vmmap`).
SHARED_CACHE_TAG = 32
STUB_TAG = 241


def host_regions(pid):
    """Process `pid`'s regions in address order, (start, end, path or "",
    user tag, protection): empty once it has ended."""
    lib = ctypes.CDLL("/usr/lib/libproc.dylib")
    buf = ctypes.create_string_buffer(REGION_SIZE)
    out = []
    at = 0
    while lib.proc_pidinfo(pid, REGION_INFO, ctypes.c_uint64(at), buf, REGION_SIZE) > 0:
        raw = buf.raw
        prot = struct.unpack_from("<I", raw, 0)[0]
        tag = struct.unpack_from("<I", raw, 32)[0]
        start, size = struct.unpack_from("<QQ", raw, 80)
        path = raw[248:].split(b"\0", 1)[0].decode(errors="replace")
        out.append((start, start + size, path, tag, prot))
        at = start + size
    return out


def proc_name(pid):
    """The name of process `pid`'s program: "" once it has ended."""
    buf = ctypes.create_string_buffer(256)
    n = ctypes.CDLL("/usr/lib/libproc.dylib").proc_name(pid, buf, len(buf))
    return buf.raw[:max(n, 0)].decode(errors="replace")


def shared_cache_name(pc):
    """The library of the host's shared cache at `pc`, and the offset into
    it: the cache is at one address in every process, so this one's
    loader names it."""

    class DlInfo(ctypes.Structure):
        _fields_ = [("fname", ctypes.c_char_p), ("fbase", ctypes.c_void_p),
                    ("sname", ctypes.c_char_p), ("saddr", ctypes.c_void_p)]

    info = DlInfo()
    if ctypes.CDLL(None).dladdr(ctypes.c_void_p(pc), ctypes.byref(info)) and info.fname:
        return f"{os.path.basename(info.fname.decode())}+{pc - info.fbase:#x}"
    return f"shared cache+{pc:#x}"


def cache_symbol(pc):
    """The function of the host's shared cache at `pc`, as this process's
    loader names it (the cache is at one address in every process), or
    ""."""

    class DlInfo(ctypes.Structure):
        _fields_ = [("fname", ctypes.c_char_p), ("fbase", ctypes.c_void_p),
                    ("sname", ctypes.c_char_p), ("saddr", ctypes.c_void_p)]

    info = DlInfo()
    if ctypes.CDLL(None).dladdr(ctypes.c_void_p(pc), ctypes.byref(info)) and info.sname:
        return f" ({info.sname.decode(errors='replace')}+{pc - info.saddr:#x})"
    return ""


def breakdown(name, execname, cmd, counts, kstacks, busiest, looks, base, where, total):
    """[`pcs`]'s readings beyond the files: the kernel's most sampled
    stacks (`kstacks`, by thread), in all and in thread `busiest`, and the
    samples in `execname` by function, named by `atos` from the binary
    `cmd` ran."""
    def name_frames(frames):
        # The program's frame it entered from, named where it can be.
        return " < ".join(where(int(f, 16)) + cache_symbol(int(f, 16)) if f.startswith("0x")
                          else f for f in frames)

    merged = collections.Counter()
    for _, n, frames in kstacks:
        merged[tuple(frames)] += n
    for frames, n in merged.most_common(8):
        print(f"{name}: kernel {n * 100 / total:.1f}%: {name_frames(frames)}", file=sys.stderr)
    for _, n, frames in sorted((k for k in kstacks if k[0] == busiest), key=lambda k: -k[1])[:6]:
        print(f"{name}: thread {busiest}: kernel {n} samples: {name_frames(frames)}",
              file=sys.stderr)
    exe = next((c for c in cmd if os.path.basename(c) == execname and os.path.isfile(c)), None)
    path = next((p for regions in looks for _, _, p, _, _ in regions
                 if p and os.path.basename(p) == execname), None)
    mine = [(pc, n) for pc, n in counts if where(pc).startswith(f"{execname}+")]
    if not exe or path is None or not mine:
        return
    lo = base[path]
    mine.sort(key=lambda c: -c[1])
    mine = mine[:2000]
    names = subprocess.run(["atos", "-o", exe, "-l", f"{lo:#x}"] + [f"{pc:#x}" for pc, _ in mine],
                           capture_output=True, text=True, errors="replace").stdout.splitlines()
    funcs = collections.Counter()
    for (_, n), sym in zip(mine, names):
        funcs[re.sub(r" \(in .*", "", sym).strip()[:100]] += n
    top = "; ".join(f"{f} {n * 100 / total:.1f}%" for f, n in funcs.most_common(15))
    print(f"{name}: {execname} by function: {top}", file=sys.stderr)
    # The host's libraries' samples, named from the shared cache.
    libs = collections.Counter()
    for pc, n in counts:
        w = where(pc)
        if "+0x" in w and not w.startswith((f"{execname}+", "anonymous")):
            libs[w] += n
    named = []
    for w, n in libs.most_common(8):
        lib, off = w.split("+")
        dylib = next((d for d in ("/usr/lib/system/" + lib, "/usr/lib/" + lib) if lib.endswith(".dylib")), None)
        sym = subprocess.run(["atos", "-o", dylib, "-l", "0x0", off], capture_output=True, text=True,
                             errors="replace").stdout.strip() if dylib else ""
        named.append(f"{w} ({sym or '?'}) {n * 100 / total:.1f}%")
    print(f"{name}: host libraries: {'; '.join(named)}", file=sys.stderr)


def rust_name(sym):
    """A Rust symbol's last two names (`jit::translation`), from its v0
    mangling; anything else as it is."""
    if not re.match(r"_*R", sym):
        return sym
    # (Crate disambiguators and back references hold digits.)
    s = re.sub(r"(?<=[CXMY])s[0-9A-Za-z]*_|B[0-9A-Za-z]*_", "", sym)
    names, i = [], 0
    while i < len(s):
        m = re.match(r"\d+", s[i:])
        if not m:
            i += 1
            continue
        n = int(m.group())
        i += len(m.group())
        names.append(s[i:i + n])
        i += n
    return "::".join(names[-2:]) or sym


def inclusive(name, execname, cmd, ustacks, busiest, samples, looks, base, where):
    """Thread `busiest`'s samples in `execname` (fwe) by function with
    what it calls ([`pcs`]'s user stacks, `samples` the thread's in all),
    named by `atos` from the binary `cmd` ran: where fwe's own work goes,
    whichever of its functions the compiler merged into which."""
    exe = next((c for c in cmd if os.path.basename(c) == execname and os.path.isfile(c)), None)
    path = next((p for regions in looks for _, _, p, _, _ in regions
                 if p and os.path.basename(p) == execname), None)
    if not exe or path is None or not samples:
        return
    # Frames DTrace named (`fwe`sym+0x10`), or left as addresses (the
    # process gone when it printed them).
    mine = [(n, [f.split("`", 1)[1].split("+")[0] if f.startswith(f"{execname}`")
                 else int(f, 16) for f in frames
                 if f.startswith(f"{execname}`")
                 or f.startswith("0x") and where(int(f, 16)).startswith(f"{execname}+")])
            for tid, n, frames in ustacks if tid == busiest]
    unique = sorted({f for _, fs in mine for f in fs if isinstance(f, int)})
    names = subprocess.run(["atos", "-o", exe, "-l", f"{base[path]:#x}"]
                           + [f"{pc:#x}" for pc in unique],
                           capture_output=True, text=True,
                           errors="replace").stdout.splitlines() if unique else []
    func = {pc: re.sub(r" \(in .*", "", sym).strip() for pc, sym in zip(unique, names)}
    funcs = collections.Counter()
    for n, fs in mine:
        for f in {rust_name(func.get(f, "?") if isinstance(f, int) else f) for f in fs}:
            funcs[f] += n
    top = "; ".join(f"{f} {n * 100 / samples:.1f}%" for f, n in funcs.most_common(30))
    print(f"{name}: thread {busiest}: {execname} by function with what it calls: {top}",
          file=sys.stderr)


def callers(name, cmd, funcs):
    """The call stacks into the host library functions `funcs` (pairs of
    library and function, DTrace's pid-provider patterns) while `cmd` (one
    fwe process) runs, by the time spent in the calls (microseconds), most
    first, named by DTrace from the process it holds."""
    out = os.path.abspath(f"bench-{re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')}.callers")
    proc = subprocess.Popen(["/bin/sh", "-c", 'read _; exec "$0" "$@"'] + cmd,
                            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    # Probes are put in fwe once it is running (after `env`'s exec too).
    proc.stdin.write(b"\n")
    proc.stdin.flush()
    for _ in range(200):
        if proc_name(proc.pid) == "fwe":
            break
        time.sleep(0.005)
    probes = " ".join(f'pid$target:{lib}:{f}:entry {{ self->t[probefunc] = timestamp; }} '
                      f'pid$target:{lib}:{f}:return /self->t[probefunc]/ {{ '
                      f'@s[probefunc, ustack(12)] = sum((timestamp - self->t[probefunc]) / 1000); '
                      f'self->t[probefunc] = 0; }}'
                      for lib, f in funcs)
    tracer = subprocess.run(["sudo", "-n", "dtrace", "-q", "-x", "aggsortrev", "-p",
                             str(proc.pid), "-n", probes + ' END { printa("%s %@d%k\\n", @s); }',
                             "-o", out],
                            capture_output=True, text=True, errors="replace", timeout=600)
    if proc.wait(timeout=600) != 0:
        print(f"{name}: the probed run exited with {proc.returncode}", file=sys.stderr)
    if not os.path.exists(out):
        said = (tracer.stdout + tracer.stderr).strip()[-600:]
        print(f"{name}: no callers (DTrace {tracer.returncode}): {said}", file=sys.stderr)
        return
    with open(out, errors="replace") as f:
        text = f.read()
    # Each stack: a line of the function and count, its frames, a blank.
    shown = 0
    for chunk in text.split("\n\n"):
        lines = [l.strip() for l in chunk.strip().splitlines() if l.strip()]
        if len(lines) < 2 or shown >= 12:
            continue
        print(f"{name}: into {lines[0]} us: {' < '.join(lines[1:])[:1500]}", file=sys.stderr)
        shown += 1


def translated(name, jit_map, counts, where):
    """The samples in fwe's translations (`counts`, by program counter),
    named by the maps of the code cache fwe wrote to directory `jit_map`:
    by what each word stands for (the program's instruction with its `x16`
    and `x17` in place or saved, or its `x18` held in `x17`, their save or
    restore, inside an expansion and of what, a lookup, a way out) and
    whether it is among a block's hot words or its cold ones, the hottest
    blocks word by word, by the program's code each block was made from
    (`where` names its address), and the hottest blocks; and the blocks
    made, by the program's code, by what ended each, and by how many
    instructions."""
    # Each block's parts: its hot words (with how many of the program's
    # words it was made from, and the last), and its cold ones.
    parts = []
    for f in os.listdir(jit_map):
        with open(os.path.join(jit_map, f)) as m:
            for line in m:
                t, size, g, kinds, words, source = line.split()
                n, last = source.split(":") if source != "cold" else (None, None)
                parts.append((int(t, 16), int(size), int(g, 16), kinds, words,
                              None if n is None else int(n),
                              None if last is None else int(last, 16)))
    parts.sort()
    starts = [b[0] for b in parts]
    blocks = [b for b in parts if b[5] is not None]
    names = {"a": "instruction", "s": "instruction, x16/x17 saved", "v": "save of x16/x17",
             "x": "instruction, x18 in x17", "r": "restore of x16/x17",
             "8": "expansion of x18", "t": "expansion of the thread pointer",
             "e": "expansion of a literal load", "i": "expansion of a cache flush",
             "c": "expansion of a system call", "l": "lookup", "L": "lookup", "o": "way out"}
    by_kind, by_code, by_block = collections.Counter(), collections.Counter(), collections.Counter()
    by_word = collections.Counter()
    # The blocks made: whose code, what ended each, how long.
    made_by, ends, lengths = collections.Counter(), collections.Counter(), collections.Counter()
    for b in blocks:
        made_by[where(b[2]).split("+")[0]] += 1
        w, n = b[6], b[5]
        ends["b" if w & 0xfc000000 == 0x14000000 else "bl" if w & 0xfc000000 == 0x94000000
             else "br" if w & 0xfffffc1f == 0xd61f0000 else "blr" if w & 0xfffffc1f == 0xd63f0000
             else "ret" if w & 0xfffffc1f == 0xd65f0000 else "the most instructions" if n >= 64
             else "the page's end or else"] += 1
        lengths["1-4" if n <= 4 else "5-8" if n <= 8 else "9-16" if n <= 16 else "17-63"
                if n < 64 else "64"] += 1

    def of(c):
        return ", ".join(f"{w} {k * 100 // len(blocks)}%" for w, k in c.most_common(8))
    print(f"{name}: blocks made: {len(blocks)}; by the program's code: {of(made_by)}; "
          f"ended by: {of(ends)}; instructions: {of(lengths)}", file=sys.stderr)
    n_in, n_cold = 0, 0
    for pc, n in counts:
        i = bisect.bisect_right(starts, pc) - 1
        if i < 0 or pc >= parts[i][0] + parts[i][1]:
            continue
        t, _, g, kinds = parts[i][:4]
        k = (pc - t) // 4
        by_word[(i, k)] += n
        by_kind[names.get(kinds[k], "?") if k < len(kinds) else "?"] += n
        by_code[where(g).split("+")[0]] += n
        by_block[g] += n
        n_in += n
        if parts[i][5] is None:
            n_cold += n
    if not n_in:
        print(f"{name}: translations: no samples ({len(blocks)} blocks)", file=sys.stderr)
        return

    def pct(c):
        return ", ".join(f"{w} {n * 100 / n_in:.0f}%" for w, n in c.most_common(8))
    hot = ", ".join(f"{where(g)} {n * 100 / n_in:.1f}%" for g, n in by_block.most_common(15))
    print(f"{name}: translations: {n_in} samples in {len(blocks)} blocks "
          f"({n_cold * 100 / n_in:.0f}% in their cold words); by word: "
          f"{pct(by_kind)}; by the program's code: {pct(by_code)}; hottest blocks: {hot}",
          file=sys.stderr)
    # The hottest blocks word by word: what each stands for, the word, and
    # its samples.
    hottest = collections.Counter()
    for (i, _), n in by_word.items():
        hottest[i] += n
    for i, _ in hottest.most_common(3):
        t, _, g, kinds, words = parts[i][:5]
        each = " ".join(f"{kinds[k]}:{words[8 * k:8 * k + 8]}:{by_word[(i, k)]}"
                        for k in range(len(kinds)))
        print(f"{name}: block {where(g)} (at {t:x}): {each}", file=sys.stderr)


def pcs(name, cmd, share=False, execname="fwe", jit_map=None):
    """Where `cmd` (an fwe process, and those it forks) runs, by the exact
    program counter of each of DTrace's samples, named by the file mapped
    there and the offset into it: `sample` walks frames, which guest code
    without frame records leaves it short of. And the time the processes
    spend in each host system call. `execname` is the processes' name:
    fwe's, or a native program's to compare with.

    What is mapped where is the first process's ([`host_regions`]), looked
    at again and again from when it runs `execname` to its end; a sample is
    named by the latest look that saw its address mapped. One look at one
    moment would miss what is mapped after it, and a look slower than the
    program (`vmmap`'s, half a second, against a compile's third) would
    see nothing.

    With `share`, it returns the samples in the program's own code and all
    of them (none when no look saw the process). A sample is fwe's in fwe
    itself, the host's libraries fwe calls (the shared cache, and anything
    under `/usr/lib` or `/System`), fwe's stubs (the regions they carry its
    memory tag in) and anything no look saw mapped; it is the program's
    anywhere else: its images and libraries, mapped or loaded into memory,
    the code it makes, and the kernel (the host's work for its system calls
    and faults, as Linux's would be). `cmd` is then one process: a forked
    one's mappings are not the first's.

    With `jit_map`, the directory fwe writes its code cache's map to as the
    process ends (`FWE_JIT_MAP`, which `cmd` sets), the samples in
    translations are named too ([`translated`])."""
    out = os.path.abspath(f"bench-{re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')}.pcs")
    # The process is made first, held until DTrace has started (DTrace
    # grabbing a running process by its pid fails while it starts), and
    # then runs `cmd` in its place. Once it exits, DTrace is interrupted
    # and writes what it gathered.
    proc = subprocess.Popen(["/bin/sh", "-c", 'read _; exec "$0" "$@"'] + cmd,
                            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    script = (f'profile-997 /execname == "{execname}"/ {{ @pc[tid, arg1] = count(); }} '
              f'profile-997 /execname == "{execname}" && arg0/ {{ @ks[tid, stack(6)] = count(); }} '
              # fwe's own stacks (frame records), for its time by function
              # with what it calls.
              + (f'profile-997 /execname == "{execname}" && arg1/ {{ @us[tid, ustack(24)] = count(); }} '
                 if execname == "fwe" else "")
              + f'syscall:::entry /execname == "{execname}"/ {{ self->t = timestamp; }} '
              'syscall:::return /self->t/ { @ns[probefunc] = sum(timestamp - self->t); '
              '@n[probefunc] = count(); self->t = 0; } '
              # Mach traps (mach_vm_*, mach_msg) are not system calls to
              # DTrace's syscall provider.
              f'mach_trap:::entry /execname == "{execname}"/ {{ self->m = timestamp; }} '
              'mach_trap:::return /self->m/ { @ns[strjoin("mach:", probefunc)] = '
              'sum(timestamp - self->m); @n[strjoin("mach:", probefunc)] = count(); '
              'self->m = 0; } '
              'END { printa("pc %d %x %@d\\n", @pc); printa("sys %s %@d %@d\\n", @ns, @n); '
              'printa("ks %d %@d%k\\nendks\\n", @ks); '
              + ('printa("us %d %@d%k\\nendus\\n", @us); ' if execname == "fwe" else "")
              + '}')
    tracer = subprocess.Popen(["sudo", "-n", "dtrace", "-q", "-x", "aggsortrev", "-n", script,
                               "-o", out],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                              errors="replace")
    time.sleep(2)
    proc.stdin.close()
    # Its regions from when it runs `execname` to its end, each look kept
    # when it differs from the last.
    looks = []
    while proc.poll() is None:
        if proc_name(proc.pid) == execname:
            regions = host_regions(proc.pid)
            # (A look its end cut short is not kept.)
            if regions and proc.poll() is None and (not looks or looks[-1] != regions):
                looks.append(regions)
        time.sleep(0.01)
    # A run that failed is said: its profile is not the work's.
    if proc.wait(timeout=300) != 0:
        print(f"{name}: the profiled run exited with {proc.returncode}", file=sys.stderr)
    # DTrace itself, sudo's child: sudo passes on no signal from a process
    # of its own process group, as this one is.
    dtrace = subprocess.run(["pgrep", "-P", str(tracer.pid)], capture_output=True,
                            text=True).stdout.split()
    subprocess.run(["sudo", "-n", "kill", "-INT"] + dtrace, capture_output=True)
    try:
        said = tracer.communicate(timeout=60)[0]
    except subprocess.TimeoutExpired:
        subprocess.run(["sudo", "-n", "kill", "-KILL"] + dtrace, capture_output=True)
        said = tracer.communicate()[0]
        sys.exit(f"{name}: DTrace did not end when interrupted: {said.strip()[-2000:]}")
    # Samples by thread, and by program counter.
    # The kernel's stacks by thread: (thread, samples, frames).
    # And fwe's user stacks the same way.
    threads, calls, kstacks = collections.defaultdict(collections.Counter), [], []
    ustacks = []
    if os.path.exists(out):
        with open(out, errors="replace") as f:
            stack, into = None, None
            for line in f:
                p = line.split()
                if stack is not None:
                    if p in (["endks"], ["endus"]):
                        into.append(stack)
                        stack = None
                    elif p:
                        stack[2].append(p[0])
                elif len(p) == 4 and p[0] == "pc":
                    threads[int(p[1])][int(p[2], 16)] += int(p[3])
                elif len(p) == 4 and p[0] == "sys":
                    calls.append((p[1], int(p[2]), int(p[3])))
                elif len(p) == 3 and p[0] in ("ks", "us"):
                    stack = (int(p[1]), int(p[2]), [])
                    into = kstacks if p[0] == "ks" else ustacks
    counts = list(sum(threads.values(), collections.Counter()).items())
    if calls:
        calls.sort(key=lambda c: -c[1])
        top = ", ".join(f"{c} {n}x {ns / 1e6:.1f} ms ({ns / n:.0f} ns)" for c, ns, n in calls[:12])
        print(f"{name}: host system calls: {sum(c[1] for c in calls) / 1e6:.1f} ms: {top}",
              file=sys.stderr)
    if not counts:
        print(f"{name}: no program counters: {said.strip()[-500:]}", file=sys.stderr)
        return None
    print(f"{name}: its regions looked at as they changed: {len(looks)} times"
          + (f", {len(looks[-1])} regions at the last" if looks else ""),
          file=sys.stderr)
    # A file's offset from the lowest address it is mapped at.
    base = {}
    for regions in looks:
        for lo, _, path, _, _ in regions:
            if path:
                base[path] = min(base.get(path, lo), lo)
    starts = [[r[0] for r in regions] for regions in looks]

    def region(pc):
        """The region at `pc` in the latest look that saw one there."""
        for regions, lows in zip(reversed(looks), reversed(starts)):
            i = bisect.bisect_right(lows, pc) - 1
            if i >= 0 and pc < regions[i][1]:
                return regions[i]
        return None

    def where(pc):
        if pc == 0:
            return "kernel"  # (No user program counter: in a system call.)
        r = region(pc)
        if r is None:
            return "unmapped"
        lo, _, path, tag, _ = r
        if path:
            return f"{os.path.basename(path)}+{pc - base[path]:#x}"
        if tag == SHARED_CACHE_TAG:
            return shared_cache_name(pc)
        return f"anonymous {lo:#x}+{pc - lo:#x}"

    total = sum(n for _, n in counts)
    by = collections.Counter()
    for pc, n in counts:
        by[where(pc).split("+")[0]] += n
    files = ", ".join(f"{w} {n * 100 // total}%" for w, n in by.most_common(8))
    top = ", ".join(f"{where(pc)} {n * 100 / total:.1f}%"
                    for pc, n in sorted(counts, key=lambda c: -c[1])[:15])
    print(f"{name}: {total} samples by program counter; by file: {files}; hottest: {top}",
          file=sys.stderr)
    # The threads that ran most: the longest of them bounds the run.
    busiest = max(threads, key=lambda t: threads[t].total())
    for tid, pcs_of in sorted(threads.items(), key=lambda t: -t[1].total())[:4]:
        of = collections.Counter()
        for pc, n in pcs_of.items():
            of[where(pc).split("+")[0]] += n
        n = pcs_of.total()
        print(f"{name}: thread {tid}: {n} samples; by file: "
              + ", ".join(f"{w} {k * 100 // n}%" for w, k in of.most_common(6)), file=sys.stderr)
    if jit_map:
        try:
            translated(name, jit_map, counts, where)
        except Exception as e:  # noqa: BLE001 (any failure of the reading itself)
            print(f"{name}: no reading of translations: {e!r}", file=sys.stderr)
    # What the kernel was doing, and fwe's samples by function: for
    # reading only, so a failure here is said and the run goes on.
    try:
        breakdown(name, execname, cmd, counts, kstacks, busiest, looks, base, where, total)
    except Exception as e:  # noqa: BLE001 (any failure of the reading itself)
        print(f"{name}: no breakdown: {e!r}", file=sys.stderr)
    # The busiest threads', and any of the four busiest that runs mostly
    # outside the program's code (a program's other threads may spend
    # theirs in fwe where its main one does not).
    def outside(pcs_of):
        mine = sum(n for pc, n in pcs_of.items()
                   if where(pc).split("+")[0] in (execname, "libsystem_malloc.dylib"))
        return mine * 2 > pcs_of.total()
    ranked = sorted(threads.items(), key=lambda t: -t[1].total())
    for tid, pcs_of in ranked[:3] + [t for t in ranked[3:4] if outside(t[1])]:
        try:
            inclusive(name, execname, cmd, ustacks, tid, pcs_of.total(), looks, base, where)
        except Exception as e:  # noqa: BLE001 (any failure of the reading itself)
            print(f"{name}: no stacks by function: {e!r}", file=sys.stderr)
    # The unnamed regions most samples are in: their tag and protection.
    hot = {w for w, _ in by.most_common(8)}
    for regions in looks:
        for lo, hi, path, tag, prot in regions:
            w = f"anonymous {lo:#x}"
            if not path and w in hot:
                hot.discard(w)
                rwx = "".join(c if prot & b else "-" for c, b in (("r", 1), ("w", 2), ("x", 4)))
                print(f"{name}: {w}: {lo:x}-{hi:x} tag {tag} {rwx}", file=sys.stderr)
    if not share:
        return None
    if not looks:
        print(f"{name}: no look saw the process's regions: no share", file=sys.stderr)
        return None

    def fwes(r):
        _, _, path, tag, _ = r
        return (tag in (STUB_TAG, SHARED_CACHE_TAG)
                or path.startswith(("/usr/lib/", "/System/"))
                or os.path.basename(path) == "fwe")

    def owns(pc):
        r = region(pc)
        return pc == 0 or (r is not None and not fwes(r))

    mine = sum(n for pc, n in counts if owns(pc))
    kernel = sum(n for pc, n in counts if pc == 0)
    print(f"{name}: the program's own code {mine * 100 / total:.1f}% (the kernel "
          f"{kernel * 100 / total:.1f}%), fwe's {(total - mine) * 100 / total:.1f}%",
          file=sys.stderr)
    return mine, total


def faulted(name, cmd):
    """The page faults of `cmd` (an fwe process) and of the processes it
    forks, apart, each named by the function of fwe's (or the file) whose
    instruction took it, with DTrace's `vminfo:::as_fault`: a fork child
    starts with no page mapped, so every page of fwe's it touches, code or
    data, is a fault, and every page either process writes after the fork
    is a copy. For reading only: a failure is said and the run goes on."""
    out = os.path.abspath(f"bench-{re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')}.faults")
    proc = subprocess.Popen(["/bin/sh", "-c", 'read _; exec "$0" "$@"'] + cmd,
                            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    first = proc.pid
    # By the faulting instruction's stack: a fault in a library (`malloc`'s,
    # mostly) is named by the function of fwe's that called it.
    script = (f'vminfo:::as_fault /execname == "fwe"/ {{ @f[pid == {first} ? 0 : 1, '
              'ustack(12)] = count(); } '
              f'proc:::exit /execname == "fwe" && pid != {first}/ {{ @kids = count(); }} '
              'END { printa("f %d %@d%k\\nendf\\n", @f); printa("kids %@d\\n", @kids); }')
    tracer = subprocess.Popen(["sudo", "-n", "dtrace", "-q", "-x", "aggsortrev", "-n", script,
                               "-o", out],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                              errors="replace")
    time.sleep(2)
    proc.stdin.close()
    looks = []
    while proc.poll() is None:
        if proc_name(proc.pid) == "fwe":
            regions = host_regions(proc.pid)
            if regions and proc.poll() is None and (not looks or looks[-1] != regions):
                looks.append(regions)
        time.sleep(0.01)
    proc.wait(timeout=300)
    dtrace = subprocess.run(["pgrep", "-P", str(tracer.pid)], capture_output=True,
                            text=True).stdout.split()
    subprocess.run(["sudo", "-n", "kill", "-INT"] + dtrace, capture_output=True)
    said = tracer.communicate(timeout=60)[0]
    # (side, faults, frames), the frames as addresses.
    stacks, kids, stack = [], 0, None
    if os.path.exists(out):
        for line in open(out, errors="replace"):
            p = line.split()
            if stack is not None:
                if p == ["endf"]:
                    stacks.append(stack)
                    stack = None
                elif p and p[0].startswith("0x"):
                    stack[2].append(int(p[0], 16))
            elif len(p) == 3 and p[0] == "f":
                stack = (int(p[1]), int(p[2]), [])
            elif len(p) == 2 and p[0] == "kids":
                kids = int(p[1])
    faults = (collections.Counter(), collections.Counter())
    for side, n, frames in stacks:
        if frames:
            faults[side][tuple(frames)] += n
    if not faults[0] and not faults[1]:
        print(f"{name}: no faults traced: {said.strip()[-500:]}", file=sys.stderr)
        return
    regions = looks[-1] if looks else []
    lows = [r[0] for r in regions]
    exe = next((c for c in cmd if os.path.basename(c) == "fwe" and os.path.isfile(c)), None)
    lo = next((r[0] for r in regions if os.path.basename(r[2]) == "fwe"), None)
    pcs = sorted({pc for side in faults for frames in side for pc in frames})
    mine = [pc for pc in pcs
            if (i := bisect.bisect_right(lows, pc) - 1) >= 0 and pc < regions[i][1]
            and os.path.basename(regions[i][2]) == "fwe"]
    names = subprocess.run(["atos", "-o", exe, "-l", f"{lo:#x}"] + [f"{pc:#x}" for pc in mine],
                           capture_output=True, text=True,
                           errors="replace").stdout.splitlines() if exe and lo and mine else []
    func = {pc: rust_name(re.sub(r" \(in .*", "", sym).strip()) for pc, sym in zip(mine, names)}

    def named(pc):
        if pc in func:
            return func[pc]
        i = bisect.bisect_right(lows, pc) - 1
        if i >= 0 and pc < regions[i][1]:
            r = regions[i]
            if r[3] == SHARED_CACHE_TAG or not r[2]:
                return (shared_cache_name(pc).split("+")[0] if r[3] == SHARED_CACHE_TAG
                        else f"anonymous (tag {r[3]})")
            return os.path.basename(r[2])
        return "unmapped (the program's)"

    def in_fwe(pc):
        i = bisect.bisect_right(lows, pc) - 1
        return i >= 0 and pc < regions[i][1] and os.path.basename(regions[i][2]) == "fwe"

    def by_caller(frames):
        # The faulting function, and the first of fwe's functions on its
        # way there where it is another's (a library's).
        leaf = named(frames[0])
        if in_fwe(frames[0]):
            return leaf
        caller = next((pc for pc in frames[1:] if in_fwe(pc)), None)
        return f"{leaf} < {named(caller)}" if caller is not None else leaf

    per = max(kids, 1)
    for side, who in ((1, "children"), (0, "the first process")):
        by = collections.Counter()
        for frames, n in faults[side].items():
            by[by_caller(frames)] += n
        total = sum(by.values())
        top = "; ".join(f"{f} {n / per:.1f}" for f, n in by.most_common(40))
        print(f"{name}: page faults of {who} per fork ({kids} forks): {total / per:.1f}: {top}",
              file=sys.stderr)


def phases(name, cmd):
    """Run `cmd` (fwe and its program) with `FWE_TIMING`, and log the time
    and the page faults between each of its marks and the one before it in
    the same process, by mark (numbers in a mark's name taken as one), as
    medians over the run: where a step that repeats (a fork, a wait) spends
    its time, and how many pages it writes (each a copy after a fork)."""
    r = subprocess.run(cmd, env=dict(os.environ, FWE_TIMING="1"), capture_output=True,
                       text=True, errors="replace")
    steps, faults = collections.defaultdict(list), collections.defaultdict(list)
    first = None
    for line in r.stderr.splitlines():
        m = re.match(r"\[fwe (\d+)\] timing: (.*?) \+(\d+)us \(\d+us\) \+(\d+) faults$",
                     line)
        if m:
            pid, m = m.group(1), m.groups()[1:]
            first = first or pid
            # The first process's steps, and those of the processes after it.
            who = "" if pid == first else "(others) "
            step = who + re.sub(r"\d+", "N", m[0])[:60]
            steps[step].append(int(m[1]))
            faults[step].append(int(m[2]))
    took = sorted(steps.items(), key=lambda kv: -sum(kv[1]))
    print(f"{name}: steps (median us, median page faults, times): "
          + "; ".join(f"{k} {statistics.median(v):.0f} us {statistics.median(faults[k]):.0f} "
                      f"faults x{len(v)}"
                      for k, v in took if len(v) > 1),
          file=sys.stderr)


def sampled(name, cmd):
    """Run `cmd` (one fwe process) under macOS's `sample`, and log where
    its time went by the top of the stack: the guest's own code (no
    symbols), or fwe's and the host libraries' functions. The sample is
    kept beside the results."""
    out = os.path.abspath(f"bench-{re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')}.sample")
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Once it has run its exec (`env -i`; Homebrew's python3 runs the
    # Python.app inside its framework): an exec ends the sampler's hold.
    time.sleep(0.05)
    sampler = subprocess.Popen(["sample", str(proc.pid), "5", "1", "-file", out],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                               errors="replace")
    # What is mapped where (the guest's libraries are files the host
    # maps), to name the guest's code in the sample: taken as it runs.
    time.sleep(0.2)
    with open(out[: -len(".sample")] + ".vmmap", "w") as f:
        subprocess.run(["vmmap", "-wide", str(proc.pid)], stdout=f, stderr=subprocess.DEVNULL)
    said = sampler.communicate()[0]
    proc.wait()
    if not os.path.exists(out):
        print(f"{name}: not sampled: {said.strip()}", file=sys.stderr)
        return
    tops = collections.Counter()
    with open(out, errors="replace") as f:
        lines = iter(f)
        for line in lines:
            if line.startswith("Sort by top of stack"):
                break
        for line in lines:
            m = re.match(r"\s+(.+?)\s+\(in ([^)]*)\)\s+(?:\[[^]]*\]\s+)?(\d+)\s*$", line)
            if not m:
                if line.strip() == "" and tops:
                    break
                continue
            sym, where, n = m.group(1), m.group(2), int(m.group(3))
            if where.startswith("<unknown") or sym.startswith("???"):
                sym, where = "guest code", "guest"
            tops[(sym[:60], where)] += n
    total = sum(tops.values()) or 1
    guest = sum(n for (_, w), n in tops.items() if w == "guest")
    top = ", ".join(f"{s} ({w}) {n * 100 // total}%" for (s, w), n in tops.most_common(12))
    print(f"{name}: {guest * 100 // total}% in guest code; top of stack: {top}", file=sys.stderr)


def rusage(name, side, cmd, fresh):
    """Log what `cmd` costs the host as `/usr/bin/time -l` reports it: user
    and system time, page faults and the largest resident size."""
    for d in fresh:
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
    r = subprocess.run(["/usr/bin/time", "-l"] + cmd, capture_output=True, text=True,
                       errors="replace")
    keep = ("real", "maximum resident", "page reclaims", "page faults", "voluntary",
            "involuntary", "instructions retired", "cycles elapsed")
    lines = [l.strip() for l in r.stderr.splitlines() if any(k in l for k in keep)]
    print(f"{name} {side}: " + "; ".join(lines), file=sys.stderr)


def profile(name, cmd, theirs, fresh, share=False):
    """[`sampled`] of `cmd` (one fwe process, after `env -i`), then a run
    with fwe's timing marks: start-up, and the code pages it wrote as they
    first ran; and what it and `theirs` cost the host ([`rusage`]).
    `fresh` is emptied before each run. Returns [`pcs`]'s figures."""
    rusage(name, "fwe", cmd, fresh)
    rusage(name, "macOS", theirs, fresh)
    for d in fresh:
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
    sampled(name, cmd)
    for d in fresh:
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
    sampled(f"{name} natively", theirs)
    for d in fresh:
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
    mine = pcs(name, cmd, share)
    for d in fresh:
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
    # (After `env -i`, which the guest's environment starts with.)
    timed = cmd[:2] + ["FWE_TIMING=1"] + cmd[2:]
    r = subprocess.run(timed, capture_output=True, text=True, errors="replace")
    marks = [l.split("timing: ", 1)[1] for l in r.stderr.splitlines() if "timing: " in l]
    print(f"{name}: fwe's marks: " + "; ".join(marks), file=sys.stderr)
    return mine


# The JDK workload's sources: a multi-threaded application, and the scale
# of its run.
JDK_SRC = os.path.join(WORKLOADS, "jdk")
JDK_SCALE = "4"


def jdk(a, fwe, guest_env, results):
    """OpenJDK 25 at work: `javac` compiling the application in
    tools/bench/workloads/jdk, then `java` running it, under fwe in its
    Alpine root, and natively with Homebrew's build of the same release."""
    root = alpine_root("jdk", a.cache)
    tmp = os.path.join(root, "tmp")
    src = os.path.join(tmp, "jdksrc")
    shutil.rmtree(src, ignore_errors=True)
    shutil.copytree(JDK_SRC, src)
    sources = sorted(f for f in os.listdir(JDK_SRC) if f.endswith(".java"))
    bin_ours = "/usr/lib/jvm/java-25-openjdk/bin"
    bin_theirs = os.path.join(a.brew, BREW["jdk"])
    native = tempfile.mkdtemp()
    ours_out, theirs_out = os.path.join(tmp, "jdkout"), os.path.join(native, "jdkout")

    def both(bindir, srcdir, out):
        files = " ".join(os.path.join(srcdir, f) for f in sources)
        # A fatal error's report where the output shows it.
        errors = "-XX:+ErrorFileToStdout"
        return (f"{bindir}/javac -J{errors} -d {out} {files} && "
                f"{bindir}/java {errors} -cp {out} Main {JDK_SCALE}")

    ours = guest_env + fwe + ["--root", root, os.path.join(root, "bin/sh"), "-c",
                              both(bin_ours, "/tmp/jdksrc", "/tmp/jdkout")]
    theirs = ["/bin/sh", "-c", both(bin_theirs, JDK_SRC, theirs_out)]
    workload(results, "JDK (s)", ours, theirs, (ours_out, theirs_out), len(guest_env) + 1)
    # Where its time goes: fwe's marks for each process (JIT code made
    # writable and prepared again, and how long that took; its system
    # calls and the host's signals).
    timed = ours[:2] + ["FWE_TIMING=1"] + ours[2:]
    r = subprocess.run(timed, capture_output=True, text=True, errors="replace")
    marks = [l.split("timing: ", 1)[1] for l in r.stderr.splitlines()
             if "timing: " in l
             and ("JIT" in l or "timing: exit +" in l or "system calls" in l)]
    print("JDK: fwe's marks: " + "; ".join(marks), file=sys.stderr)
    # Where `javac`'s time goes, by program counter: one process, so its
    # mappings name each sample (translated code is in fwe's code cache).
    shutil.rmtree(ours_out, ignore_errors=True)
    os.makedirs(ours_out)
    javac = guest_env + fwe + ["--root", root, os.path.join(root, bin_ours.lstrip("/"), "javac"),
                               "-d", "/tmp/jdkout"] + [f"/tmp/jdksrc/{f}" for f in sources]
    jit_map = tempfile.mkdtemp()
    pcs("JDK javac", guest_env + [f"FWE_JIT_MAP={jit_map}"] + javac[len(guest_env):],
        jit_map=jit_map)
    shutil.rmtree(jit_map, ignore_errors=True)

    # And natively, for what the same work costs the host's kernel.
    shutil.rmtree(theirs_out, ignore_errors=True)
    os.makedirs(theirs_out)
    pcs("JDK javac natively", [f"{bin_theirs}/javac", "-d", theirs_out]
        + [os.path.join(JDK_SRC, f) for f in sources], execname="javac")
    # The application's run, both ways, from the classes just compiled.
    jit_map = tempfile.mkdtemp()
    pcs("JDK java", guest_env + [f"FWE_JIT_MAP={jit_map}"] + fwe
        + ["--root", root, os.path.join(root, bin_ours.lstrip("/"), "java"), "-cp", "/tmp/jdkout",
           "Main", JDK_SCALE], jit_map=jit_map)
    shutil.rmtree(jit_map, ignore_errors=True)
    # Where its threads wait on fwe's own locks.
    try:
        java = os.path.join(root, bin_ours.lstrip("/"), "java")
        callers("JDK java", guest_env + fwe + ["--root", root, java, "-cp", "/tmp/jdkout", "Main",
                                               JDK_SCALE],
                [("libsystem_kernel.dylib", "__psynch_mutexwait")])
    except Exception as e:  # noqa: BLE001 (any failure of the reading itself)
        print(f"JDK java: no callers: {e!r}", file=sys.stderr)
    pcs("JDK java natively", [f"{bin_theirs}/java", "-cp", theirs_out, "Main", JDK_SCALE],
        execname="java")
    # What the translator's work is (`FWE_TIMING`'s counts): `javac` twice
    # into one directory of the blocks made (`FWE_JIT_SEEN`), then `java`
    # into it too, for how many blocks an earlier run made; then each with
    # its blocks counting their runs (`FWE_JIT_COUNT`).
    java = guest_env + fwe + ["--root", root, os.path.join(root, bin_ours.lstrip("/"), "java"),
                              "-cp", "/tmp/jdkout", "Main", JDK_SCALE]
    seen = tempfile.mkdtemp()
    for label, cmd, extra in [
            ("javac", javac, [f"FWE_JIT_SEEN={seen}"]),
            ("javac again", javac, [f"FWE_JIT_SEEN={seen}"]),
            ("java after them", java, [f"FWE_JIT_SEEN={seen}"]),
            ("javac with its blocks counting", javac, ["FWE_JIT_COUNT=1"]),
            ("java with its blocks counting", java, ["FWE_JIT_COUNT=1"])]:
        r = subprocess.run(guest_env + ["FWE_TIMING=1"] + extra + cmd[len(guest_env):],
                           capture_output=True, text=True, errors="replace")
        said = [line.split("; blocks made ", 1)[1] for line in r.stderr.splitlines()
                if "timing: exit: " in line and "; blocks made " in line]
        print(f"JDK {label}, the translator's counts (exit {r.returncode}): "
              + " | ".join("blocks made " + s for s in said), file=sys.stderr)
        if label == "javac again":
            # A file's code's blocks a run made again that an earlier
            # made at the same address with the same words (none: they
            # are kept).
            again = [int(m.group(1)) for m in
                     (re.search(r"made before by another process: from files (\d+) at the same", s)
                      for s in said) if m]
            print(f"JDK javac again: blocks of files' code an earlier run made, made again: "
                  f"{sum(again)}", file=sys.stderr)
    shutil.rmtree(seen, ignore_errors=True)
    # How long `javac` takes alone, both ways: the median of three rounds,
    # taken in turn (a runner's load moves in minutes).
    took = ([], [])
    for _ in range(3):
        for side, (out, cmd) in enumerate(
                [(ours_out, javac), (theirs_out, [f"{bin_theirs}/javac", "-d", theirs_out]
                                     + [os.path.join(JDK_SRC, f) for f in sources])]):
            shutil.rmtree(out, ignore_errors=True)
            os.makedirs(out)
            start = time.perf_counter()
            subprocess.run(cmd, capture_output=True)
            took[side].append(time.perf_counter() - start)
    print(f"JDK javac alone: {statistics.median(took[0]):.2f} s under fwe, "
          f"{statistics.median(took[1]):.2f} s natively (medians of "
          f"{', '.join(f'{t:.2f}' for t in took[0])} and {', '.join(f'{t:.2f}' for t in took[1])})",
          file=sys.stderr)
    # What its JIT compilers did, both ways (`-XX:+CITime`, said as the
    # JVM ends): how many methods each tier compiled, in how long.
    at = javac.index("-d")
    for how, out, cmd in [
            ("under fwe", ours_out, javac[:at] + ["-J-XX:+CITime"] + javac[at:]),
            ("natively", theirs_out, [f"{bin_theirs}/javac", "-J-XX:+CITime", "-d", theirs_out]
             + [os.path.join(JDK_SRC, f) for f in sources])]:
        shutil.rmtree(out, ignore_errors=True)
        os.makedirs(out)
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
        said = [" ".join(line.split()) for line in r.stdout.splitlines()
                if re.search(r"Total compil|C[12] {|Tier[1-4] {|nmethod code size", line)]
        print(f"JDK javac's compilers {how}: " + "; ".join(said), file=sys.stderr)
    # How long each part of the application takes, both ways (it says on
    # standard error).
    for how, cmd in [("under fwe", guest_env + fwe + [
            "--root", root, os.path.join(root, bin_ours.lstrip("/"), "java"), "-cp",
            "/tmp/jdkout", "Main", JDK_SCALE]),
            ("natively", [f"{bin_theirs}/java", "-cp", theirs_out, "Main", JDK_SCALE])]:
        start = time.perf_counter()
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
        took = time.perf_counter() - start
        print(f"JDK java parts {how} ({took:.2f} s in all): "
              + ", ".join(r.stderr.split("\n")).strip(", "), file=sys.stderr)
    # How long the JVM takes to start and end with no application.
    took = []
    for cmd in [guest_env + fwe + ["--root", root, os.path.join(root, bin_ours.lstrip("/"), "java"),
                                   "-version"],
                [f"{bin_theirs}/java", "-version"]]:
        start = time.perf_counter()
        subprocess.run(cmd, capture_output=True)
        took.append(time.perf_counter() - start)
    print(f"JDK java -version: {took[0]:.2f} s under fwe, {took[1]:.2f} s natively", file=sys.stderr)
    shutil.rmtree(native, ignore_errors=True)


def workloads(a, fwe, guest_env, lua_src, results):
    """The workloads of Python, SQLite, git and xz: under fwe in their
    Alpine root, natively with Homebrew's builds of them. git and xz work on
    the Lua sources in `lua_src` (copied into the root)."""
    root = alpine_root("workloads", a.cache)
    tmp = os.path.join(root, "tmp")
    shutil.copytree(WORKLOADS, os.path.join(tmp, "wl"), dirs_exist_ok=True)
    src = os.path.join(tmp, "luasrc")
    shutil.rmtree(src, ignore_errors=True)
    os.makedirs(src)
    for f in os.listdir(lua_src):
        if f.endswith((".c", ".h")):
            shutil.copy(os.path.join(lua_src, f), src)
    native = tempfile.mkdtemp()
    ours_w, theirs_w = os.path.join(tmp, "w"), os.path.join(native, "w")
    brew = {k: os.path.join(a.brew, v) for k, v in BREW.items()}

    def under(prog, *args):
        return guest_env + fwe + ["--root", root, os.path.join(root, prog.lstrip("/"))] + list(args)

    def script(name, prog_ours, prog_theirs):
        return (
            under("/bin/sh", "-c", f"cd /tmp/w && sh /tmp/wl/{name} /tmp/luasrc {prog_ours}"),
            ["/bin/sh", "-c", f"cd {theirs_w} && sh {WORKLOADS}/{name} {lua_src} {prog_theirs}"],
        )

    fresh = (ours_w, theirs_w)
    at = len(guest_env) + 1  # after fwe itself
    workload(
        results,
        "Python script (s)",
        under("/usr/bin/python3", "/tmp/wl/bench.py"),
        [brew["python"], os.path.join(WORKLOADS, "bench.py")],
        (),
        at,
        profiled=True,
        share=True,
    )
    workload(
        results,
        "SQLite (s)",
        under("/usr/bin/sqlite3", "/tmp/w/db", ".read /tmp/wl/bench.sql"),
        [brew["sqlite"], os.path.join(theirs_w, "db"), f".read {WORKLOADS}/bench.sql"],
        fresh,
        at,
        profiled=True,
    )
    workload(results, "git (s)", *script("git.sh", "/usr/bin/git", brew["git"]), fresh, at)
    git_commands(*script("git.sh", "/usr/bin/git", brew["git"]), fresh, root)
    # `git status` in the workload's repository, again and again: the
    # command whose share differs most.
    for d in fresh:
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
    for cmd in script("git.sh", "/usr/bin/git", brew["git"]):
        subprocess.run(cmd, capture_output=True, check=True)
    loop = "cd {} && i=0; while [ $i -lt 100 ]; do {} status --porcelain >/dev/null; i=$((i+1)); done"
    statuses = {"fwe": under("/bin/sh", "-c", loop.format("/tmp/w", "/usr/bin/git")),
                "macOS": ["/bin/sh", "-c", loop.format(theirs_w, brew["git"])]}
    for side, cmd in statuses.items():
        t = time.perf_counter()
        subprocess.run(cmd, capture_output=True, check=True)
        print(f"git status {side}: {(time.perf_counter() - t) * 10:.2f} ms each", file=sys.stderr)
    pcs("git status", statuses["fwe"])
    # Commits, one after another: the command whose share differs most.
    loop = ("cd /tmp/w && i=0; while [ $i -lt 20 ]; do echo $i >> src/lua.c; "
            "/usr/bin/git commit -q -am $i; i=$((i+1)); done")
    pcs("git commit", under("/bin/sh", "-c", loop))
    pcs("git commit natively", ["/bin/sh", "-c", loop.replace("/tmp/w", theirs_w).replace(
        "/usr/bin/git", brew["git"])], execname="git")
    # Its history with patches, one process: where git's own code goes.
    pcs("git log -p", under("/usr/bin/git", "-C", "/tmp/w", "log", "-p"))
    # One git process's start, where the workload's seventy go.
    one = under("/usr/bin/git", "--version")
    timed = one[:2] + ["FWE_TIMING=1"] + one[2:]
    r = subprocess.run(timed, capture_output=True, text=True, errors="replace")
    marks = [l.split("timing: ", 1)[1] for l in r.stderr.splitlines() if "timing: " in l]
    print("git --version: fwe's marks: " + "; ".join(marks), file=sys.stderr)
    starts = {"fwe": one, "macOS": [brew["git"], "--version"]}
    for side, cmd in starts.items():
        rusage("git --version", side, cmd, ())
        t = time.perf_counter()
        for _ in range(20):
            subprocess.run(cmd, capture_output=True)
        print(f"git --version {side}: {(time.perf_counter() - t) / 20 * 1e3:.2f} ms each",
              file=sys.stderr)
    # And started from a shell inside, as the workload's are: forked, then
    # the program loaded in place.
    loop = "i=0; while [ $i -lt 50 ]; do {} --version >/dev/null; i=$((i+1)); done"
    inside = {"fwe": under("/bin/sh", "-c", loop.format("/usr/bin/git")),
              "macOS": ["/bin/sh", "-c", loop.format(brew["git"])]}
    for side, cmd in inside.items():
        t = time.perf_counter()
        subprocess.run(cmd, capture_output=True)
        print(f"git --version from a shell, {side}: {(time.perf_counter() - t) / 50 * 1e3:.2f} ms each",
              file=sys.stderr)
    workload(results, "xz (s)", *script("xz.sh", "/usr/bin/xz", brew["xz"]), fresh, at)
    for d in fresh:
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
    pcs("xz (s)", script("xz.sh", "/usr/bin/xz", brew["xz"])[0])
    # And xz alone, on the data that left (its code named by its library's
    # offsets, not its shell's): its two runs, each one process, are the
    # workload's share of fwe's.
    # (Decompressing sixty times over: once is over in a few samples.)
    mine = [pcs("xz -6", under("/usr/bin/xz", "-6", "-T1", "-c", "-k", "/tmp/w/data"), True),
            pcs("xz -d", under("/usr/bin/xz", "-d", "-T1", "-c", "-k", *["/tmp/w/data.xz"] * 60),
                True)]
    if all(mine):
        results.setdefault(SHARE, {})["xz (s)"] = (
            sum(m[1] for m in mine) / max(sum(m[0] for m in mine), 1))
    shutil.rmtree(native, ignore_errors=True)


def render(results):
    cols = [c for c in ("fwe", FWE_VM, "macOS", "Linux", VM) if c in results]
    against = [c for c in ("macOS", VM) if c in results]
    rows = list(results["fwe"].keys())
    shares = results.get(SHARE, {})
    ran = results.get(BACKEND, {})
    lines = [
        "| benchmark | fwe's backend | " + " | ".join(cols) + "".join(f" | fwe / {c}" for c in against)
        + " | fwe's share | budget |",
        "|---" * (len(cols) + len(against) + 4) + "|",
    ]
    for row in rows:
        vals = [results[c].get(row) for c in cols]
        ratios = [f"{results['fwe'][row] / results[c][row]:.1f}x" if results[c].get(row) else ""
                  for c in against]
        cells = ["" if v is None else f"{v:.1f}" if v >= 10 else f"{v:.2f}" for v in vals]
        share = f"{shares[row]:.2f}x" if row in shares else ""
        budget = (f"{BUDGETS[row]}x" if row in BUDGETS
                  else f"{SHARE_BUDGETS[row]}x of share" if row in SHARE_BUDGETS
                  else f"at most {LIMITS[row]}" if row in LIMITS else "")
        lines.append(f"| {row} | {ran.get(row, '')} | " + " | ".join(cells + ratios) + f" | {share} | {budget} |")
    return "\n".join(lines)


def write(path, r):
    with open(path, "w") as f:
        json.dump(r, f, indent=2)
    print(json.dumps(r, indent=2))


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="mode", required=True)
    lx = sub.add_parser("linux")
    lx.add_argument("--bench", required=True)
    lx.add_argument("--cache", required=True)
    lx.add_argument("--out", required=True)
    lx.add_argument("--xvfb", required=True, help="an Xvfb, for the X benchmarks")
    mc = sub.add_parser("macos")
    mc.add_argument("--fwe", required=True)
    mc.add_argument("--bench", required=True)
    mc.add_argument("--native", required=True)
    mc.add_argument("--cache", required=True)
    mc.add_argument("--linux")
    mc.add_argument("--linux-vm", help="results of `linux` in a Linux VM on this Mac (vm.sh)")
    mc.add_argument("--fwe-vm", help="results of `macos` with fwe's VM backend (vm.sh)")
    mc.add_argument("--no-build", action="store_true")
    mc.add_argument("--brew", required=True, help="Homebrew's prefix: the native programs")
    mc.add_argument("--out", required=True)
    mc.add_argument("--xvfb", required=True, help="an Xvfb, for the X benchmarks")
    a = p.parse_args()
    {"linux": linux, "macos": macos}[a.mode](a)


if __name__ == "__main__":
    main()
