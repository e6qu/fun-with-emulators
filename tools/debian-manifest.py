#!/usr/bin/env python3
"""Make a Debian manifest (guests/debian/fetch/<name>.txt) again from what
its header names:

    # suite: trixie
    # seeds: nodejs
    # only-seeds: yes        (optional: the seeds alone, no closure)

    python3 tools/debian-manifest.py guests/debian/fetch/node.txt...

The suite's arm64 index (dists/<suite>/main/binary-arm64/Packages.xz) is
fetched from deb.debian.org and checked against the SHA-256 its InRelease
file gives. A manifest is a whole system: the seeds, every package Debian
marks Essential (the C library, the shells, coreutils...), and every
package they depend on (Pre-Depends and Depends, the first alternative the
index has, a package chosen already preferred, a virtual name through
Provides). Each line is a pool path and the package's SHA-256. The header
keeps the description above its keys, and records the snapshot of the
archive the files are in (snapshot.debian.org), which the tests fetch from
once deb.debian.org has replaced a version.
"""

import hashlib
import lzma
import os
import re
import sys
import time
import urllib.request

MIRROR = "https://deb.debian.org/debian"
CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "target", "debian-index")


def fetch(url):
    with urllib.request.urlopen(url, timeout=120) as r:
        return r.read()


def index(suite):
    """The suite's arm64 packages, by name (the first of a name wins)."""
    os.makedirs(CACHE, exist_ok=True)
    release = fetch(f"{MIRROR}/dists/{suite}/InRelease").decode()
    want = re.search(r"^ ([0-9a-f]{64})\s+\d+ main/binary-arm64/Packages\.xz$", release, re.M)
    if not want:
        sys.exit(f"{suite}: InRelease names no main/binary-arm64/Packages.xz")
    path = os.path.join(CACHE, f"{suite}-{want.group(1)[:16]}.xz")
    if not os.path.exists(path):
        data = fetch(f"{MIRROR}/dists/{suite}/main/binary-arm64/Packages.xz")
        if hashlib.sha256(data).hexdigest() != want.group(1):
            sys.exit(f"{suite}: Packages.xz does not match InRelease")
        with open(path + ".part", "wb") as f:
            f.write(data)
        os.replace(path + ".part", path)
    pkgs = {}
    for block in lzma.open(path, "rt", encoding="utf-8").read().split("\n\n"):
        f = dict(l.split(": ", 1) for l in block.split("\n") if ": " in l and not l[0].isspace())
        if "Package" in f:
            pkgs.setdefault(f["Package"], f)
    return pkgs


def closure(pkgs, seeds):
    provides = {}
    for n, f in pkgs.items():
        for p in f.get("Provides", "").split(","):
            p = p.strip().split(" ")[0]
            if p:
                provides.setdefault(p, []).append(n)
    chosen = {}
    todo = list(reversed(seeds))
    while todo:
        n = todo.pop()
        if n in chosen:
            continue
        if n not in pkgs:
            cands = provides.get(n, [])
            if not cands:
                sys.exit(f"no package {n}")
            n = next((c for c in cands if c in chosen), cands[0])
            if n in chosen:
                continue
        chosen[n] = pkgs[n]
        for field in ("Pre-Depends", "Depends"):
            for dep in pkgs[n].get(field, "").split(","):
                if not dep.strip():
                    continue
                alts = [a.strip().split(" ")[0].split(":")[0] for a in dep.split("|")]
                if any(a in chosen for a in alts):
                    continue
                pick = next((a for a in alts if a in pkgs or a in provides), None)
                if pick is None:
                    sys.exit(f"{n}: nothing satisfies {dep.strip()}")
                todo.append(pick)
    return chosen


def make(manifest):
    lines = open(manifest).read().splitlines()
    header = [l for l in lines if l.startswith("#")]
    keys = {}
    for l in header:
        m = re.match(r"# (suite|seeds|only-seeds|snapshot): (.*)$", l)
        if m:
            keys[m.group(1)] = m.group(2).strip()
    if "suite" not in keys or "seeds" not in keys:
        sys.exit(f"{manifest}: its header names no suite or seeds")
    pkgs = index(keys["suite"])
    seeds = keys["seeds"].split()
    if keys.get("only-seeds") == "yes":
        chosen = {n: pkgs[n] for n in seeds}
    else:
        essential = sorted(n for n, f in pkgs.items() if f.get("Essential") == "yes")
        chosen = closure(pkgs, seeds + essential)
    snapshot = time.strftime("%Y%m%dT000000Z", time.gmtime(time.time() - 86400))
    described = [l for l in header if not re.match(r"# (suite|seeds|only-seeds|snapshot):", l)]
    out = described + [
        f"# suite: {keys['suite']}",
        f"# seeds: {keys['seeds']}",
    ]
    if keys.get("only-seeds") == "yes":
        out.append("# only-seeds: yes")
    out.append(f"# snapshot: {snapshot}")
    body = sorted(f"{f['Filename']} {f['SHA256']}" for f in chosen.values())
    with open(manifest, "w") as f:
        f.write("\n".join(out + body) + "\n")
    size = sum(int(f["Size"]) for f in chosen.values())
    print(f"{manifest}: {len(chosen)} packages, {size / 1e6:.0f} MB")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    for m in sys.argv[1:]:
        make(m)
