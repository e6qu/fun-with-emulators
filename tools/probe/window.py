"""TEMPORARY probe: fs_usage lines of the test's processes, and anyone's on
its directory, between the file's write and the symlink."""
import re, sys
lines = open(sys.argv[1], errors="replace").read().splitlines()
start = None
for i, l in enumerate(lines):
    if "file.txt" in l and " close " in l:
        start = i
    if "symlinkat" in l and start is not None:
        pids = set(re.findall(r"fwe\.(\d+)\s*$", lines[start]) + re.findall(r"fwe\.(\d+)\s*$", l))
        print(f"=== window {lines[start][:16]} .. {l[:16]}, fwe pids {pids}")
        for m in lines[start:i + 2]:
            p = re.search(r"(\S+)\.(\d+)\s*$", m)
            if (p and p.group(2) in pids) or "LTP_lst" in m or "file.txt" in m:
                print(m[:40] + " ... " + m[-120:].strip())
        start = None
