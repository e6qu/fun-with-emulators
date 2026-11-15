#!/usr/bin/env python3
"""fwe's benchmarks: startup, system calls, fork/exec, threads, a C
project's build and programs' realistic workloads, under fwe, natively on
macOS and natively on Linux.

    run.py linux --bench BENCH --cache DIR --out linux.json
        On arm64 Linux: BENCH (guests/c/bench.c, built static-pie) runs
        natively; Lua is built, and the workloads run, in an Alpine 3.24
        container (docker).

    run.py macos --fwe FWE --bench BENCH --native NATIVE --brew PREFIX
                 --cache DIR [--linux linux.json] [--no-build] --out macos.json
        On macOS: BENCH (the Linux build) runs under FWE; NATIVE (the same
        source built for macOS) runs natively. Lua is built with clang under
        FWE in an Alpine root (guests/alpine/fetch/clang.txt, fetched into
        DIR), and natively with Homebrew's clang of the same release (under
        PREFIX); the workloads (tools/bench/workloads: Lua, Python, SQLite,
        git and xz) run under FWE in an Alpine root of those programs
        (guests/alpine/fetch/workloads.txt) and natively with Homebrew's
        builds of them, each side's output checked against the other's.
        `--linux-vm` adds the same benchmarks run in a Linux VM on the
        same Mac (tools/bench/vm.sh), with fwe's ratio to them.
        With the Linux results, a table of all three is printed (and
        appended to $GITHUB_STEP_SUMMARY). `--no-build` leaves the build and
        the workloads out (Alpine's programs run only in CI). It fails when
        a figure of fwe's exceeds its budget against macOS's (BUDGETS), or
        a computing program's share of fwe's its own (SHARE_BUDGETS).

Each figure is the best of several runs: the machines are shared, and the
best is the least disturbed.
"""

import argparse
import collections
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROUNDS = 9

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
                ["curl", "-sfL", "--retry", "5", "--retry-all-errors", "-o", path + ".part", u]
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
        subprocess.run(["tar", "--xattrs", "-xzf", f] + args + ["-C", root], check=True)
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
]


# How many times native macOS's figure fwe's may be, on the same runner
# (PLAN.md, "Native speed"): system calls 1.5x, the process and thread
# calls and start-up 3x, a C build 1.5x.
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
    "build Lua (s)": 1.5,
    # Programs at work that are mostly system calls (a database on disk, a
    # repository), as a call is.
    "SQLite (s)": 1.5,
    "git (s)": 1.5,
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
SHARE_BUDGETS = {
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
    def pair(f, g, rounds=ROUNDS):
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
    """The benchmarks whose fwe / macOS ratio exceeds its budget, or whose
    share of fwe's exceeds its share budget. A missing figure is one: the
    budget is not shown to hold."""
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
    shutil.rmtree(native, ignore_errors=True)


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
            r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
            times[side].append(time.perf_counter() - start)
            if r.returncode != 0:
                sys.exit(f"{name} {side} failed ({r.returncode}): {r.stderr[-3000:]}")
            outs[side] = r.stdout
    if outs["fwe"] != outs["macOS"]:
        sys.exit(f"{name}: fwe printed {outs['fwe']!r}, macOS {outs['macOS']!r}")
    for side in times:
        results[side][name] = min(times[side])
    for d in fresh:
        shutil.rmtree(d, ignore_errors=True)
        os.makedirs(d)
    trace = os.path.abspath(f"bench-{name.split()[0].lower()}.trace")
    subprocess.run(
        ours[:at] + ["--strace", f"--strace-file={trace}"] + ours[at:], capture_output=True
    )
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


def pcs(name, cmd, share=False, execname="fwe"):
    """Where `cmd` (an fwe process, and those it forks) runs, by the exact
    program counter of each of DTrace's samples, named by the file mapped
    there (as `vmmap` lists it in the first process while it runs) and the
    offset into it: `sample` walks frames, which guest code without frame
    records leaves it short of. And the time the processes spend in each
    host system call. `execname` is the processes' name: fwe's, or a native
    program's to compare with.

    With `share`, it returns the samples in the program's own code and all
    of them. A sample is fwe's in fwe itself, the host's libraries fwe
    calls, fwe's stubs (the regions they carry its memory tag in,
    "Memory Tag 241") and anything `vmmap` did not see mapped; it is the
    program's anywhere else: its images and libraries, mapped or loaded
    into memory, the code it makes, and the kernel (the host's work for its
    system calls and faults, as Linux's would be). `cmd` is then one
    process: a forked one's mappings are not the first's."""
    out = os.path.abspath(f"bench-{re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-')}.pcs")
    # The process is made first, held until DTrace has started (DTrace
    # grabbing a running process by its pid fails while it starts), and
    # then runs `cmd` in its place. Once it exits, DTrace is interrupted
    # and writes what it gathered.
    proc = subprocess.Popen(["/bin/sh", "-c", 'read _; exec "$0" "$@"'] + cmd,
                            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    script = (f'profile-997 /execname == "{execname}"/ {{ @pc[arg1] = count(); }} '
              f'syscall:::entry /execname == "{execname}"/ {{ self->t = timestamp; }} '
              'syscall:::return /self->t/ { @ns[probefunc] = sum(timestamp - self->t); '
              '@n[probefunc] = count(); self->t = 0; } '
              'END { printa("pc %x %@d\\n", @pc); printa("sys %s %@d %@d\\n", @ns, @n); }')
    tracer = subprocess.Popen(["sudo", "-n", "dtrace", "-q", "-x", "aggsortrev", "-n", script,
                               "-o", out],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                              errors="replace")
    time.sleep(2)
    proc.stdin.close()
    time.sleep(0.25)
    regions = []
    vm = subprocess.run(["vmmap", "-wide", str(proc.pid)], capture_output=True, text=True,
                        errors="replace").stdout
    for line in vm.splitlines():
        m = re.search(r"([0-9a-f]+)-([0-9a-f]+)\s+\[.*?\]\s+\S+\s+SM=\S+\s*(.*)$", line)
        if m:
            regions.append((int(m.group(1), 16), int(m.group(2), 16), m.group(3).strip(),
                            " ".join(line.split())))
    proc.wait(timeout=300)
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
    counts, calls = [], []
    if os.path.exists(out):
        with open(out, errors="replace") as f:
            for line in f:
                p = line.split()
                if len(p) == 3 and p[0] == "pc":
                    counts.append((int(p[1], 16), int(p[2])))
                elif len(p) == 4 and p[0] == "sys":
                    calls.append((p[1], int(p[2]), int(p[3])))
    if calls:
        calls.sort(key=lambda c: -c[1])
        top = ", ".join(f"{c} {n}x {ns / 1e6:.1f} ms ({ns / n:.0f} ns)" for c, ns, n in calls[:12])
        print(f"{name}: host system calls: {sum(c[1] for c in calls) / 1e6:.1f} ms: {top}",
              file=sys.stderr)
    if not counts:
        print(f"{name}: no program counters: {said.strip()[-500:]}", file=sys.stderr)
        return None
    # A file's offset from the lowest address it is mapped at.
    base = {}
    for lo, _, what, _ in regions:
        if what:
            base[what] = min(base.get(what, lo), lo)

    def where(pc):
        if pc == 0:
            return "kernel"  # (No user program counter: in a system call.)
        for lo, hi, what, _ in regions:
            if lo <= pc < hi:
                return f"{os.path.basename(what)}+{pc - base[what]:#x}" if what else f"anonymous {lo:#x}+{pc - lo:#x}"
        return "unmapped"

    total = sum(n for _, n in counts)
    by = collections.Counter()
    for pc, n in counts:
        by[where(pc).split("+")[0]] += n
    files = ", ".join(f"{w} {n * 100 // total}%" for w, n in by.most_common(8))
    top = ", ".join(f"{where(pc)} {n * 100 / total:.1f}%"
                    for pc, n in sorted(counts, key=lambda c: -c[1])[:15])
    print(f"{name}: {total} samples by program counter; by file: {files}; hottest: {top}",
          file=sys.stderr)
    # What vmmap says of the unnamed regions most samples are in.
    for w, _ in by.most_common(8):
        for lo, _, what, line in regions:
            if not what and w == f"anonymous {lo:#x}":
                print(f"{name}: {w}: {line}", file=sys.stderr)
    if not share:
        return None

    def fwes(what, line):
        return (line.startswith("Memory Tag 241")
                or what.startswith(("/usr/lib/", "/System/"))
                or os.path.basename(what) == "fwe")

    def owns(pc):
        return pc == 0 or any(lo <= pc < hi and not fwes(what, line)
                              for lo, hi, what, line in regions)

    mine = sum(n for pc, n in counts if owns(pc))
    kernel = sum(n for pc, n in counts if pc == 0)
    print(f"{name}: the program's own code {mine * 100 / total:.1f}% (the kernel "
          f"{kernel * 100 / total:.1f}%), fwe's {(total - mine) * 100 / total:.1f}%",
          file=sys.stderr)
    return mine, total


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
    # (Decompressing sixty times over: once is over before `vmmap` has
    # looked.)
    mine = [pcs("xz -6", under("/usr/bin/xz", "-6", "-T1", "-c", "-k", "/tmp/w/data"), True),
            pcs("xz -d", under("/usr/bin/xz", "-d", "-T1", "-c", "-k", *["/tmp/w/data.xz"] * 60),
                True)]
    if all(mine):
        results.setdefault(SHARE, {})["xz (s)"] = (
            sum(m[1] for m in mine) / max(sum(m[0] for m in mine), 1))
    shutil.rmtree(native, ignore_errors=True)


def render(results):
    cols = [c for c in ("fwe", "macOS", "Linux", VM) if c in results]
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
                  else f"{SHARE_BUDGETS[row]}x of share" if row in SHARE_BUDGETS else "")
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
    mc = sub.add_parser("macos")
    mc.add_argument("--fwe", required=True)
    mc.add_argument("--bench", required=True)
    mc.add_argument("--native", required=True)
    mc.add_argument("--cache", required=True)
    mc.add_argument("--linux")
    mc.add_argument("--linux-vm", help="results of `linux` in a Linux VM on this Mac (vm.sh)")
    mc.add_argument("--no-build", action="store_true")
    mc.add_argument("--brew", required=True, help="Homebrew's prefix: the native programs")
    mc.add_argument("--out", required=True)
    a = p.parse_args()
    {"linux": linux, "macos": macos}[a.mode](a)


if __name__ == "__main__":
    main()
