#!/usr/bin/env python3
"""fwe's benchmarks: startup, system calls, fork/exec, threads and a C
project's build, under fwe, natively on macOS and natively on Linux.

    run.py linux --bench BENCH --cache DIR --out linux.json
        On arm64 Linux: BENCH (guests/c/bench.c, built static-pie) runs
        natively; Lua is built in an Alpine 3.24 container (docker).

    run.py macos --fwe FWE --bench BENCH --native NATIVE --cache DIR
                 [--linux linux.json] [--no-build] --out macos.json
        On macOS: BENCH (the Linux build) runs under FWE; NATIVE (the same
        source built for macOS) runs natively; Lua is built under FWE in an
        Alpine root with GCC and make (guests/alpine/fetch/gcc.txt, fetched
        into DIR), and natively with the host's compiler. With the Linux
        results, a table of all three is printed (and appended to
        $GITHUB_STEP_SUMMARY). `--no-build` leaves the build out (Alpine's
        programs run only in CI).

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

ROUNDS = 5

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
    ("thread create+join", ["thread", "2000"], "us"),
    ("fork+exit+wait", ["fork", "200"], "us"),
]


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


def unpack_lua(tarball, into):
    subprocess.run(["tar", "-xzf", tarball, "-C", into], check=True)
    return os.path.join(into, "lua-5.4.7")


def checked(cmd, retrace=None):
    """Run `cmd`; on failure, show the end of its output and, with
    `retrace` (fwe's trace options), run it once more traced, then stop."""
    r = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    if r.returncode == 0:
        return
    print(f"failed ({r.returncode}): {' '.join(cmd)}", file=sys.stderr)
    print((r.stdout + r.stderr)[-4000:], file=sys.stderr)
    if retrace:
        subprocess.run(cmd[:1] + retrace + cmd[1:], capture_output=True)
        print(f"traced to {retrace[-1]}", file=sys.stderr)
    sys.exit(1)


def lua_build_s(cmd_for, src, retrace=None):
    """Seconds to build Lua from clean with `cmd_for(make_args)`, best of
    three."""

    def once():
        checked(cmd_for(["clean"]))
        start = time.perf_counter()
        checked(cmd_for(["-j4", "posix"]), retrace)
        return time.perf_counter() - start

    return best(once, 3)


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
                ["docker", "exec", name, "apk", "add", "-q", "gcc", "make", "musl-dev", "binutils"],
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
    results = {
        "fwe": micro(fwe, a.bench),
        "macOS": micro([], a.native),
    }
    if not a.no_build:
        build(a, fwe, results)
    if a.linux:
        with open(a.linux) as f:
            results["Linux"] = json.load(f)
    write(a.out, results)
    table = render(results)
    print(table)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as f:
            f.write(table + "\n")


def build(a, fwe, results):
    """Lua built under fwe with Alpine's GCC, in the root's /tmp, and
    natively with the host's compiler."""
    lua = fetch(*LUA, a.cache)
    root = alpine_root("gcc", a.cache)
    tmp = os.path.join(root, "tmp")
    os.makedirs(tmp, exist_ok=True)
    shutil.rmtree(os.path.join(tmp, "lua-5.4.7"), ignore_errors=True)
    src = unpack_lua(lua, tmp)
    make = fwe + ["--root", root, os.path.join(root, "usr/bin/make"), "-C", "/tmp/lua-5.4.7"]
    trace = os.path.abspath("bench-trace.txt")
    results["fwe"]["build Lua (s)"] = lua_build_s(
        lambda args: make + args, src, ["--strace", f"--strace-file={trace}"]
    )
    # The Lua it built runs.
    out = subprocess.run(
        fwe + ["--root", root, os.path.join(src, "src/lua"), "-e", "print(6*7)"],
        check=True,
        capture_output=True,
        text=True,
    )
    if out.stdout.strip() != "42":
        sys.exit(f"the Lua fwe built printed {out.stdout!r}")
    native = tempfile.mkdtemp()
    native_src = unpack_lua(lua, native)
    results["macOS"]["build Lua (s)"] = lua_build_s(
        lambda args: ["make", "-C", native_src] + args, native_src
    )
    shutil.rmtree(native, ignore_errors=True)


def render(results):
    cols = [c for c in ("fwe", "macOS", "Linux") if c in results]
    rows = list(results["fwe"].keys())
    lines = ["| benchmark | " + " | ".join(cols) + " | fwe / macOS |", "|---" * (len(cols) + 2) + "|"]
    for row in rows:
        vals = [results[c].get(row) for c in cols]
        ratio = (
            f"{results['fwe'][row] / results['macOS'][row]:.1f}x"
            if results["macOS"].get(row)
            else ""
        )
        cells = ["" if v is None else f"{v:.1f}" if v >= 10 else f"{v:.2f}" for v in vals]
        lines.append(f"| {row} | " + " | ".join(cells) + f" | {ratio} |")
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
