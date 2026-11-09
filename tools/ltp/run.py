#!/usr/bin/env python3
"""Run LTP's system-call tests under fwe and compare with the baseline.

Usage: tools/ltp/run.py --fwe target/debug/fwe --root OUT/root
                        [--baseline tools/ltp/baseline.txt] [--update]
                        [--jobs N] [--only REGEX] [--results FILE]

The root is a root filesystem with LTP in /opt/ltp (tools/ltp/build.sh
makes it, of Alpine's minirootfs). Each entry of LTP's runtest/syscalls runs as `fwe --root ROOT <test>
<args>`, in a directory of its own under `/tmp` (its TMPDIR), with LTP's
own per-test timeout and a hard limit above that; `--jobs` run at once, but
those that change a machine-wide setting (see SERIAL) run one at a time,
after the rest. A test passes when it exits 0; LTP's exit status
otherwise says why (TCONF, 32: not applicable here). The baseline lists the
tests that pass; a run fails if any of them does not (a regression), and
`--update` rewrites it from the run. The pass rate is printed either way.
"""

import argparse
import concurrent.futures
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time

# LTP's exit statuses (include/tst_res_flags.h), as bits.
TFAIL, TBROK, TWARN, TCONF = 1, 2, 4, 32
# A hard limit on each test, over LTP's own (30 s per run by default, times
# LTP_TIMEOUT_MUL below; tests that run longer raise it themselves and
# report as they go).
HARD_LIMIT = 300
# The System V IPC and message queue tests: each runs in an IPC namespace of
# its own. They fill, count and limit what a namespace holds, which tests
# run beside them (four at a time, where LTP runs one) would otherwise see
# and change.
IPC_TESTS = re.compile(r"^(shm|sem|msg|ipc|mq_)")
# A test that runs away with processes must not take the host with it: the
# tests have this many processes beyond those the user had as the run began
# (a host's limit counts all of the user's, and a CI runner's user has
# hundreds of its own; futex_cmp_requeue01 forks a thousand).
PROCESS_HEADROOM = 1500


def process_limit():
    """The user's process limit for the tests: what it runs now, and
    PROCESS_HEADROOM more."""
    found = subprocess.run(["ps", "-U", str(os.getuid()), "-o", "pid="], capture_output=True, text=True)
    return len(found.stdout.split()) + PROCESS_HEADROOM


PROCESS_LIMIT = process_limit()


def prepare(root):
    """The root's /tmp, where each test gets a directory."""
    tmp = os.path.join(root, "tmp")
    os.makedirs(tmp, exist_ok=True)
    os.chmod(tmp, 0o1777)
    # The host gives a new file its directory's group: the user's own, as
    # in a checkout, wherever the root is (a group the guest sees as
    # another's would change what tests of ownership find).
    os.chown(tmp, -1, os.getegid())
    return tmp


def entries(ltp):
    """(name, argv) of each test in runtest/syscalls."""
    out = []
    with open(os.path.join(ltp, "runtest", "syscalls")) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name, *argv = shlex.split(line)
            out.append((name, argv or [name]))
    return out


def classify(status):
    if status == 0:
        return "pass"
    if status < 0:
        return "signal"
    if status & TBROK:
        return "broken"
    if status & TFAIL:
        return "fail"
    if status & TWARN:
        return "warn"
    if status == TCONF:
        return "conf"
    return f"exit-{status}"


def session(sid):
    """The processes of session `sid` (macOS's `pkill` and `pgrep` cannot
    select by session)."""
    ps = subprocess.run(["ps", "-axo", "pid="], capture_output=True, text=True).stdout.split()
    out = []
    for pid in map(int, ps):
        try:
            if os.getsid(pid) == sid:
                out.append(pid)
        except OSError:
            pass
    return out


def end_session(sid):
    """Kill every process of session `sid`."""
    for pid in session(sid):
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


def end_leftovers(fwe, root):
    """End what tests left running outside their sessions (a child stopped
    and orphaned, a daemon of its own): every process of this fwe on this
    root, once no test runs. Returns how many there were. They count
    against the user's processes, which a test that forks a thousand
    (futex_cmp_requeue01) needs."""
    found = subprocess.run(
        ["pgrep", "-f", "^" + re.escape(f"{fwe} --root {root} ")], capture_output=True, text=True
    )
    pids = [int(p) for p in found.stdout.split() if int(p) > 0]
    for pid in pids:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    return len(pids)


def stacks(sid, work):
    """The stacks of the processes of session `sid`, as macOS's `sample`
    takes them: fwe's own frames, a few lines a thread."""
    out = []
    for pid in map(str, session(sid)[:8]):
        path = os.path.join(work, f"sample-{pid}.txt")
        subprocess.run(["sample", pid, "1", "-file", path], capture_output=True, timeout=60)
        try:
            with open(path) as f:
                lines = [l.rstrip() for l in f if "fwe_" in l or "Thread_" in l or "libsystem_kernel" in l]
            os.remove(path)
        except OSError:
            continue
        out.append(f"--- stacks of {pid}:")
        out.extend(l[:220] for l in lines[:60])
    return "\n" + "\n".join(out) + "\n"


def run_one(fwe, root, work, name, argv, hard_limit=HARD_LIMIT):
    """Run one test; (name, outcome, seconds, output tail)."""
    bindir = "/opt/ltp/testcases/bin"
    prog = argv[0] if "/" in argv[0] else f"{bindir}/{argv[0]}"
    host_prog = os.path.join(root, prog.lstrip("/"))
    if not os.path.isfile(host_prog):
        return name, "missing", 0.0, ""
    with open(host_prog, "rb") as f:
        if f.read(4) != b"\x7fELF":
            # A shell script: LTP's shell library is not built.
            return name, "script", 0.0, ""
    tmp = tempfile.mkdtemp(prefix=name[:40] + ".", dir=work)
    # Open to every user, as /tmp is: tests drop to an unprivileged user.
    os.chmod(tmp, 0o1777)
    guest_tmp = "/" + os.path.relpath(tmp, root)
    env = {
        "PATH": f"{bindir}:/usr/sbin:/usr/bin:/sbin:/bin",
        "TMPDIR": guest_tmp,
        "LTPROOT": "/opt/ltp",
        "LTP_COLORIZE_OUTPUT": "0",
        # A test given a device puts tmpfs on it, the filesystem fwe has
        # (LTP's default is ext2).
        "LTP_DEV_FS_TYPE": "tmpfs",
        # A fork under fwe takes milliseconds, not Linux's tenth of one: a
        # test that forks thousands of times (fork14) is given eight times
        # LTP's time. One that runs for a set time instead (fork13's ten
        # minutes) runs a tenth of it: the same checks, fewer rounds.
        "LTP_TIMEOUT_MUL": "8",
        "LTP_RUNTIME_MUL": "0.1",
        "HOME": guest_tmp,
        "LANG": "C",
    }
    start = time.monotonic()
    # Output to a file, not a pipe: a process the test leaves behind, in a
    # process group of its own, would hold a pipe open and the read would
    # never end. The process limit is set by a shell for the test (the
    # runner's threads make a `preexec_fn` unsafe), in a session of its own
    # so everything it starts can be found and ended.
    command = [fwe, "--root", root, host_prog, *argv[1:]]
    if IPC_TESTS.match(name):
        busybox = os.path.join(root, "bin", "busybox")
        command = [fwe, "--root", root, busybox, "unshare", "-i", "--", prog, *argv[1:]]
    with tempfile.TemporaryFile(dir=work) as log:
        proc = subprocess.Popen(
            # (At most the host's hard limit, when that is lower.)
            ["/bin/sh", "-c", f'ulimit -u {PROCESS_LIMIT} 2>/dev/null || ulimit -u "$(ulimit -H -u)"; exec "$@"', "sh", *command],
            cwd=tmp,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            proc.wait(timeout=hard_limit)
            outcome = classify(proc.returncode)
        except subprocess.TimeoutExpired:
            outcome = "timeout"
            # Where each of its processes is stuck, for the record (a test
            # that hangs is a bug of fwe's to find).
            log.write(stacks(proc.pid, work).encode())
        # It, and whatever it left running in its session (in process
        # groups of its own, some of it).
        end_session(proc.pid)
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            pass
        log.seek(0)
        out = log.read()
    shutil.rmtree(tmp, ignore_errors=True)
    keep = 400 if outcome == "timeout" else 40
    tail = "\n".join(out.decode(errors="replace").splitlines()[-keep:])
    return name, outcome, time.monotonic() - start, tail


def run_guarded(fwe, root, work, name, argv, hard_limit=HARD_LIMIT):
    """`run_one`, a failure of the runner itself (starting a test while
    another has the host short of processes, say) retried once, then
    reported as the outcome."""
    for attempt in range(2):
        try:
            return run_one(fwe, root, work, name, argv, hard_limit)
        except Exception as e:  # noqa: BLE001 - reported, and fails the run
            if attempt == 1:
                return name, "runner-error", 0.0, repr(e)
            time.sleep(1)


# Tests that change a machine-wide setting (a sysctl: fork13 lowers
# kernel.pid_max, which getpid01 checks pids against) and put it back as
# they end: run one at a time, after the rest, so that none of them takes
# another's change for the setting to restore, nor runs while another's is
# in force.
SERIAL = re.compile(r"^(fcntl30|fcntl35|fcntl37|splice06|vmsplice04|fork13)(_64)?$")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fwe", required=True)
    ap.add_argument("--root", required=True, help="a root filesystem with LTP in /opt/ltp")
    ap.add_argument("--baseline", default=os.path.join(os.path.dirname(__file__), "baseline.txt"))
    ap.add_argument("--update", action="store_true", help="rewrite the baseline from this run")
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    ap.add_argument("--only", help="run only the tests whose name matches")
    ap.add_argument("--results", help="write every outcome to this file")
    ap.add_argument("--show", action="store_true", help="print the output of each test that does not pass")
    ap.add_argument("--hard-limit", type=int, default=HARD_LIMIT, help="seconds before a test is ended")
    args = ap.parse_args()

    fwe = os.path.abspath(args.fwe)
    root = os.path.abspath(args.root)
    tests = entries(os.path.join(root, "opt", "ltp"))
    if args.only:
        tests = [t for t in tests if re.search(args.only, t[0])]
    work = tempfile.mkdtemp(prefix="fwe-ltp.", dir=prepare(root))
    os.chmod(work, 0o1777)
    results = {}
    try:
        done = 0

        def report(name, outcome, secs, tail):
            nonlocal done
            done += 1
            results[name] = outcome
            print(f"[{done}/{len(tests)}] {name}: {outcome} ({secs:.1f}s)", flush=True)
            if args.show and outcome not in ("pass", "conf", "script", "missing"):
                print("    " + tail.replace("\n", "\n    "), flush=True)

        parallel = [(n, a) for n, a in tests if not SERIAL.match(n)]
        serial = [(n, a) for n, a in tests if SERIAL.match(n)]
        with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
            futures = [pool.submit(run_guarded, fwe, root, work, n, a, args.hard_limit) for n, a in parallel]
            for fut in concurrent.futures.as_completed(futures):
                report(*fut.result())
        left = end_leftovers(fwe, root)
        if left:
            print(f"ended {left} processes tests left running")
        for n, a in serial:
            report(*run_guarded(fwe, root, work, n, a, args.hard_limit))
    finally:
        shutil.rmtree(work, ignore_errors=True)

    if args.results:
        with open(args.results, "w") as f:
            for name in sorted(results):
                f.write(f"{name} {results[name]}\n")

    counts = {}
    for outcome in results.values():
        counts[outcome] = counts.get(outcome, 0) + 1
    passed = counts.get("pass", 0)
    run = len(results) - counts.get("script", 0) - counts.get("missing", 0)
    applicable = run - counts.get("conf", 0)
    print("\noutcomes: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))
    print(f"passed {passed} of {run} run ({100 * passed / max(run, 1):.1f}%), "
          f"{passed} of {applicable} applicable ({100 * passed / max(applicable, 1):.1f}%)")

    if args.update:
        with open(args.baseline, "w") as f:
            f.write("# LTP system-call tests that pass under fwe (tools/ltp/run.py --update).\n")
            for name in sorted(n for n, o in results.items() if o == "pass"):
                f.write(name + "\n")
        print(f"baseline: {passed} tests written to {args.baseline}")
        return 0

    with open(args.baseline) as f:
        baseline = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    regressed = [n for n in baseline if n in results and results[n] != "pass"]
    newly = sorted(n for n, o in results.items() if o == "pass" and n not in set(baseline))
    if newly:
        print(f"passing, not in the baseline ({len(newly)}): " + " ".join(newly))
    if regressed:
        # Once more, alone: a test timed against a loaded machine may have
        # missed its moment. One that passes so is named, not failed.
        argv_of = dict(tests)
        work = tempfile.mkdtemp(prefix="fwe-ltp.", dir=prepare(root))
        os.chmod(work, 0o1777)
        try:
            end_leftovers(fwe, root)
            again = {n: run_guarded(fwe, root, work, n, argv_of[n]) for n in regressed}
        finally:
            shutil.rmtree(work, ignore_errors=True)
        flaky = [n for n in regressed if again[n][1] == "pass"]
        if flaky:
            print(f"passed when run again alone ({len(flaky)}): " + " ".join(flaky))
        for n in regressed:
            if again[n][1] != "pass" and args.show:
                print(f"--- {n} ({again[n][1]}), run again:\n" + again[n][3])
        regressed = [n for n in regressed if again[n][1] != "pass"]
    if regressed:
        print(f"REGRESSED ({len(regressed)}): " + " ".join(f"{n}={results[n]}" for n in regressed))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
