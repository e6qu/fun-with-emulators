#!/usr/bin/env python3
"""Run LTP's system-call tests under fwe and compare with the baseline.

Usage: tools/ltp/run.py --fwe target/debug/fwe --root OUT/root
                        [--baseline tools/ltp/baseline.txt] [--update]
                        [--jobs N] [--only REGEX] [--results FILE]

The root is a root filesystem with LTP in /opt/ltp (tools/ltp/build.sh
makes it, of Alpine's minirootfs). Each entry of LTP's runtest/syscalls runs as `fwe --root ROOT <test>
<args>`, in a directory of its own under `/tmp` (its TMPDIR), with LTP's
own per-test timeout and a hard limit above that (four times it for the slow
ones, which start first; a minute for one not in the baseline); `--jobs`
run at once, but those that change a machine-wide setting or measure time
(see SERIAL) run one at a time, after the rest. A test passes when it exits 0; LTP's exit status
otherwise says why (TCONF, 32: not applicable here). The baseline lists the
tests that pass; a run fails if any of them does not (a regression), and
`--update` rewrites it from the run. A regression is run again alone; a
timer test that then fails only by sleeping too long is measured against
the host's own timers (hosttimer.c), and named, not failed, if they, with
fwe's least cost per sleep, miss the same threshold. The pass rate is printed either way.
The tests in exceptions.txt, which fail or skip on Linux too or test what is
not planned, are not run, and do not count as applicable; a test that skips
and is not among them is named (what fwe still lacks).
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
# Tests that take tens of seconds or more, however well fwe does: started
# first.
SLOW = re.compile(
    r"^(shmget03|fcntl14|fcntl14_64|rename11|renameat01|shmctl05|inotify11"
    r"|semop05|msgstress01|preadv203|preadv203_64|linkat02|fork14|munmap04|fallocate06)$"
)

# A hard limit on each test, over LTP's own (30 s per run by default, times
# LTP_TIMEOUT_MUL below; tests that run longer raise it themselves and
# report as they go).
HARD_LIMIT = 300
# A test not in the baseline fails already: it is not given the time a
# regression would be, so one that hangs costs a minute, not five.
FAILING_LIMIT = 60
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
        # test is given eight times LTP's time, a slow one thirty-two, as
        # its hard limit is four times the rest's (fork14's 16,394 forks of
        # a process with as many mappings take macOS minutes natively, a
        # CI runner several times this). One
        # that runs for a set time instead (fork13's ten minutes) runs a
        # tenth of it: the same checks, fewer rounds.
        "LTP_TIMEOUT_MUL": "32" if SLOW.match(name) else "8",
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
    # (A timer test's every measurement, for `host_timers_late`.)
    keep = 400 if outcome == "timeout" or b"slept for too long" in out else 40
    tail = "\n".join(out.decode(errors="replace").splitlines()[-keep:])
    return name, outcome, time.monotonic() - start, tail


TIMER_SET = re.compile(r"sleeping for (\d+)us (\d+) iterations, threshold ([\d.]+)us")
TIMER_RESULT = re.compile(r"min (\d+)us, .*trunc mean ([\d.]+)us")


def host_timers_late(work, tail):
    """For a timer test (LTP's tst_timer_test) whose only failures are
    sleeps that ended too late: evidence, as lines, that the host made each
    late sleep late itself, or none. The host's own sleeps of the same
    length are measured (hosttimer.c, up to three rounds); fwe's least cost
    per sleep is what its shortest sleep took past the host's shortest.
    The host made the sleep late when its mean, with that cost, is past
    LTP's threshold already."""
    lines = tail.splitlines()
    fails = [line for line in lines if "TFAIL" in line]
    if not fails or any("slept for too long" not in line for line in fails):
        return []
    late_sets = []
    for i, line in enumerate(lines):
        m = TIMER_SET.search(line)
        res = next((TIMER_RESULT.search(x) for x in lines[i + 1:i + 3] if TIMER_RESULT.search(x)), None)
        if m and res:
            usec, n, threshold = int(m[1]), int(m[2]), float(m[3])
            if float(res[2]) > usec + threshold:
                late_sets.append((usec, n, threshold, int(res[1])))
    if not late_sets:
        return []
    probe = os.path.join(work, "hosttimer")
    if not os.path.exists(probe):
        source = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hosttimer.c")
        if subprocess.run(["cc", "-O2", "-o", probe, source]).returncode != 0:
            return []
    found = []
    for usec, n, threshold, fwe_min in late_sets:
        for _ in range(3):
            r = subprocess.run([probe, str(usec), str(n)], capture_output=True, text=True)
            try:
                host_min, host_mean, host_max = (float(x) for x in r.stdout.split())
            except ValueError:
                return []
            cost = max(0.0, fwe_min - host_min)
            if host_mean + cost > usec + threshold:
                found.append(
                    f"{usec}us x{n}: host mean {host_mean:.0f}us (min {host_min:.0f}, max {host_max:.0f})"
                    f" + fwe's least cost {cost:.0f}us > {usec + threshold:.0f}us"
                )
                break
        else:
            return []
    return found


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


# Tests run one at a time, after the rest: those that change a
# machine-wide setting (a sysctl: fork13 lowers kernel.pid_max, which
# getpid01 checks pids against) and put it back as they end, so that none
# takes another's change for the setting to restore, nor runs while
# another's is in force; and those that measure time (how late a sleep or a
# timeout ends, timer slack) or need the host's processors (fork14's 16384
# forks of a process with as many mappings, quadratic on the host), which a
# loaded machine makes miss.
SERIAL = re.compile(
    r"^(fcntl30|fcntl35|fcntl37|splice06|vmsplice04|fork13"
    r"|fork14|prctl09|select02|poll02|pselect01|epoll_pwait03|epoll_wait02"
    r"|clock_gettime04|clock_nanosleep02|nanosleep01|futex_wait05|pipe15)(_64)?$"
)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fwe", required=True)
    ap.add_argument("--root", required=True, help="a root filesystem with LTP in /opt/ltp")
    ap.add_argument("--baseline", default=os.path.join(os.path.dirname(__file__), "baseline.txt"))
    ap.add_argument(
        "--exceptions",
        default=os.path.join(os.path.dirname(__file__), "exceptions.txt"),
        help="tests not run: they fail on Linux too, the file says why",
    )
    ap.add_argument("--update", action="store_true", help="rewrite the baseline from this run")
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    ap.add_argument("--only", help="run only the tests whose name matches")
    ap.add_argument("--results", help="write every outcome to this file")
    ap.add_argument("--show", action="store_true", help="print the output of each test that does not pass")
    ap.add_argument("--hard-limit", type=int, default=HARD_LIMIT, help="seconds before a test is ended")
    ap.add_argument(
        "--failing-limit",
        type=int,
        default=FAILING_LIMIT,
        help="seconds before a test not in the baseline is ended",
    )
    args = ap.parse_args()

    fwe = os.path.abspath(args.fwe)
    root = os.path.abspath(args.root)
    tests = entries(os.path.join(root, "opt", "ltp"))
    if args.only:
        tests = [t for t in tests if re.search(args.only, t[0])]
    # The exceptions are not run (some wait out their whole timeout).
    excepted = set()
    if os.path.exists(args.exceptions):
        with open(args.exceptions) as f:
            excepted = {line.split()[0] for line in f if line.strip() and not line.startswith("#")}
    results = {n: "exception" for n, _ in tests if n in excepted}
    with open(args.baseline) as f:
        passing = {line.strip() for line in f if line.strip() and not line.startswith("#")}
    if args.update:
        passing = {n for n, _ in tests}

    def limit(name):
        # A slow test is given four times the time, passing yet or not:
        # its time is mostly the host's (fork14's thousands of forks of a
        # process with thousands of mappings).
        if SLOW.match(name):
            return 4 * args.hard_limit
        return args.hard_limit if name in passing else min(args.failing_limit, args.hard_limit)

    tests = [t for t in tests if t[0] not in excepted]
    work = tempfile.mkdtemp(prefix="fwe-ltp.", dir=prepare(root))
    os.chmod(work, 0o1777)
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
        # The long ones first, so that the many short ones fill in beside
        # them rather than leaving them to run on alone at the end.
        parallel.sort(key=lambda t: not SLOW.match(t[0]))
        serial = [(n, a) for n, a in tests if SERIAL.match(n)]
        # The slow ones last: what they leave the host to do as they end
        # (fork14's thousands of large address spaces torn down) would
        # disturb the timing of the next.
        serial.sort(key=lambda t: bool(SLOW.match(t[0])))
        with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
            futures = [pool.submit(run_guarded, fwe, root, work, n, a, limit(n)) for n, a in parallel]
            for fut in concurrent.futures.as_completed(futures):
                report(*fut.result())
        left = end_leftovers(fwe, root)
        if left:
            print(f"ended {left} processes tests left running")
        for n, a in serial:
            report(*run_guarded(fwe, root, work, n, a, limit(n)))
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
    applicable = run - counts.get("conf", 0) - counts.get("exception", 0)
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
    skipped = sorted(n for n, o in results.items() if o == "conf")
    if skipped:
        print(f"skipped, not in the exceptions ({len(skipped)}): " + " ".join(skipped))
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
        # A timer test the host's own timers fail too: the host cannot
        # time as LTP asks (a CI runner, a virtual machine, is late now and
        # then by milliseconds), so it is named with the evidence, not
        # failed. One the host meets is fwe's to fix.
        work = tempfile.mkdtemp(prefix="fwe-ltp.", dir=prepare(root))
        try:
            host_late = {n: host_timers_late(work, again[n][3]) for n in regressed}
        finally:
            shutil.rmtree(work, ignore_errors=True)
        host_late = {n: v for n, v in host_late.items() if v}
        if host_late:
            print(f"late as the host's own timers are ({len(host_late)}): " + " ".join(host_late))
            for n, found in host_late.items():
                print(f"    {n}: " + "; ".join(found))
        regressed = [n for n in regressed if n not in host_late]
    if regressed:
        print(f"REGRESSED ({len(regressed)}): " + " ".join(f"{n}={results[n]}" for n in regressed))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
