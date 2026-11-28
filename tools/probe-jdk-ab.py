#!/usr/bin/env python3
# Probe: the JDK benchmark's workload under main's fwe, this branch's fwe
# and natively, rounds interleaved (the order turning each round).
import os, sys, time, statistics, subprocess, shutil, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "bench"))
import run as bench
cache, roots, brew, fmain, fbranch = sys.argv[1:6]
root = bench.alpine_root("jdk", cache, roots)
tmp = os.path.join(root, "tmp")
src = os.path.join(tmp, "jdksrc")
shutil.rmtree(src, ignore_errors=True)
shutil.copytree(bench.JDK_SRC, src)
sources = sorted(f for f in os.listdir(bench.JDK_SRC) if f.endswith(".java"))
native = tempfile.mkdtemp()
def both(bindir, srcdir, out):
    files = " ".join(os.path.join(srcdir, f) for f in sources)
    return f"{bindir}/javac -d {out} {files} && {bindir}/java -cp {out} Main {bench.JDK_SCALE}"
guest_env = ["env", "-i", "PATH=/usr/bin:/bin", "HOME=/root"]
ours = lambda fwe: guest_env + [fwe, "--root", root, os.path.join(root, "bin/sh"), "-c", both("/usr/lib/jvm/java-25-openjdk/bin", "/tmp/jdksrc", "/tmp/jdkout")]
sides = {"main": (ours(fmain), os.path.join(tmp, "jdkout")), "branch": (ours(fbranch), os.path.join(tmp, "jdkout")),
         "native": (["/bin/sh", "-c", both(os.path.join(brew, bench.BREW["jdk"]), bench.JDK_SRC, os.path.join(native, "jdkout"))], os.path.join(native, "jdkout"))}
times = {k: [] for k in sides}
order = list(sides)
for r in range(12):
    for side in order:
        cmd, out = sides[side]
        shutil.rmtree(out, ignore_errors=True); os.makedirs(out)
        t = time.perf_counter()
        p = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL)
        times[side].append(time.perf_counter() - t)
        if p.returncode != 0:
            sys.exit(f"{side} failed: {p.stderr[-2000:]}")
    print(f"round {r}: " + ", ".join(f"{s} {times[s][-1]:.2f}" for s in order), flush=True)
    order = order[1:] + order[:1]
for s, t in times.items():
    print(f"{s}: best {min(t):.2f}, median {statistics.median(t):.2f}, all " + " ".join(f"{x:.2f}" for x in t))
for s in ("main", "branch"):
    print(f"{s} / native: best {min(times[s]) / min(times['native']):.2f}x, median {statistics.median(times[s]) / statistics.median(times['native']):.2f}x")
