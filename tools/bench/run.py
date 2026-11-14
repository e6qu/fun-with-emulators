#!/usr/bin/env python3
"""fwe's benchmarks: startup, system calls, fork/exec, threads and a C
project's build, under fwe, natively on macOS and natively on Linux.

    run.py linux --bench BENCH --cache DIR --out linux.json
        On arm64 Linux: BENCH (guests/c/bench.c, built static-pie) runs
        natively; Lua is built in an Alpine 3.24 container (docker).

    run.py macos --fwe FWE --bench BENCH --native NATIVE --cache DIR
                 [--linux linux.json] [--no-build] --out macos.json
        On macOS: BENCH (the Linux build) runs under FWE; NATIVE (the same
        source built for macOS) runs natively; Lua is built with clang
        under FWE in an Alpine root (guests/alpine/fetch/clang.txt, fetched
        into DIR), and natively with the host's clang. With the Linux
        results, a table of all three is printed (and appended to
        $GITHUB_STEP_SUMMARY). `--no-build` leaves the build out (Alpine's
        programs run only in CI). It fails when a figure of fwe's exceeds
        its budget (BUDGETS) against macOS's, or for the build against
        Linux's, which runs the same toolchain (AGAINST).

Each figure is the best of several runs: the machines are shared, and the
best is the least disturbed.
"""

import argparse
import hashlib
import json
import os
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
    "thread create+join (us)": 3.0,
    "fork+exit+wait (us)": 3.0,
    "fork+exec+wait (us)": 3.0,
    "build Lua (s)": 1.5,
}

# The figures held to a budget against another than macOS's: the build,
# against Linux's, which runs the same Alpine clang as fwe does (macOS's
# is Apple's clang, another compiler, which says nothing of fwe).
AGAINST = {"build Lua (s)": "Linux"}


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
    return best(lambda: lua_build_once(cmd_for, retrace), 3)


def lua_build_once(cmd_for, retrace=None):
    """Seconds to build Lua from clean once with `cmd_for(make_args)`."""
    checked(cmd_for(["clean"]))
    start = time.perf_counter()
    checked(cmd_for(["-j4", "posix", "CC=clang"]), retrace)
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
    results = {"fwe": ours, "macOS": theirs}
    if not a.no_build:
        build(a, fwe, results)
    if a.linux:
        with open(a.linux) as f:
            results["Linux"] = json.load(f)
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
    """The benchmarks whose ratio to their reference (macOS, or AGAINST's)
    exceeds its budget. A reference missing is a failure: the budget is
    not shown to hold."""
    over = []
    for row, budget in BUDGETS.items():
        against = AGAINST.get(row, "macOS")
        fwe, ref = results["fwe"].get(row), results.get(against, {}).get(row)
        if fwe is None:
            continue
        if not ref:
            over.append(f"{row}: no {against} figure")
        elif fwe / ref > budget:
            over.append(f"{row} {fwe / ref:.1f}x > {budget}x against {against}")
    return over


def build(a, fwe, results):
    """Lua built with clang under fwe, in an Alpine root's /tmp (the guest
    given only its own environment), and natively with the host's clang."""
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
        ours.append(lua_build_once(lambda args: make + args, traced))
        theirs.append(lua_build_once(lambda args: ["make", "-C", native_src] + args))
    shutil.rmtree(native, ignore_errors=True)
    results["fwe"]["build Lua (s)"] = min(ours)
    results["macOS"]["build Lua (s)"] = min(theirs)
    # The Lua it built runs.
    out = subprocess.run(
        fwe + ["--root", root, os.path.join(src, "src/lua"), "-e", "print(6*7)"],
        check=True,
        capture_output=True,
        text=True,
    )
    if out.stdout.strip() != "42":
        sys.exit(f"the Lua fwe built printed {out.stdout!r}")


def render(results):
    cols = [c for c in ("fwe", "macOS", "Linux") if c in results]
    rows = list(results["fwe"].keys())
    lines = [
        "| benchmark | " + " | ".join(cols) + " | fwe / macOS | budget |",
        "|---" * (len(cols) + 3) + "|",
    ]
    for row in rows:
        vals = [results[c].get(row) for c in cols]
        ratio = (
            f"{results['fwe'][row] / results['macOS'][row]:.1f}x"
            if results["macOS"].get(row)
            else ""
        )
        cells = ["" if v is None else f"{v:.1f}" if v >= 10 else f"{v:.2f}" for v in vals]
        budget = f"{BUDGETS[row]}x" if row in BUDGETS else ""
        if row in AGAINST and results.get(AGAINST[row], {}).get(row):
            r = results["fwe"][row] / results[AGAINST[row]][row]
            budget += f" ({r:.1f}x against {AGAINST[row]})"
        lines.append(f"| {row} | " + " | ".join(cells) + f" | {ratio} | {budget} |")
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
    mc.add_argument("--no-build", action="store_true")
    mc.add_argument("--out", required=True)
    a = p.parse_args()
    {"linux": linux, "macos": macos}[a.mode](a)


if __name__ == "__main__":
    main()
