# Plan

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)
when, and only when, they appear in all capitals, as shown here.

## Goal

Unmodified Linux arm64 programs on macOS (Apple Silicon), without a Linux
kernel and faster than a Linux VM on the same Mac: command-line programs
and toolchains, language runtimes and their JIT compilers, container
engines and their images, graphical programs, Windows programs through
Linux's Wine, and gVisor's sandbox. fwe is written in Rust.

## Approach

fwe implements Linux's user-space ABI on macOS, as Wine implements
Windows' and WSL1 implemented Linux's on Windows. A program's code runs
directly on the CPU inside an `fwe` process; its system calls go to fwe's
kernel layer: processes, threads, memory, files, signals, networking,
namespaces and cgroups, with fwe's own `/proc`, `/sys` and `/dev`.

Two backends share that layer:
- **Native**, in-process: every position-independent program, and
  executables whose link kept their relocations, moved above the 4 GiB
  macOS reserves.
- **Hypervisor**: a minimal Hypervisor.framework VM, CPU and memory only,
  for the other executables linked below 4 GiB and for programs that need
  4 KiB pages.

A VM running a Linux kernel is a non-goal.
[docs/architecture.md](docs/architecture.md) describes each part.

## Scope

In scope: Linux's user-space ABI on arm64 (system calls, ELF loading,
signals, `/proc`, `/sys`, `/dev`, ioctls, namespaces, cgroups);
distributions' userlands (Debian, Alpine); container engines and standard
images; gVisor's `runsc`; Wine for ARM64 Windows programs, console and
graphical; graphical Linux programs on an X server on the Mac, with OpenGL
and Vulkan on its GPU.

Out of scope: kernel modules and private kernel interfaces, hardware
drivers, and x86 binaries (Linux or Windows).

## 1.0

Reached when, as [ROADMAP.md](ROADMAP.md) defines them:
- the target programs (git, compilers, Node, Go, Rust, apt, a database, a
  web server, a JDK) run unmodified, those in the VM on real hardware;
- Docker, Podman and containerd build and run images, rootless Podman
  included;
- every LTP system-call test passes but those for what is not planned and
  those that fail on Linux too, each listed with its reason;
- `strace` and `gdb` work on a guest program;
- Linux code runs at native speed and what fwe adds holds the benchmark
  budgets;
- graphical Linux programs and Windows programs through Wine draw on the
  Mac's screen, on its GPU;
- a JDK workload runs inside gVisor on fwe;
- a signed release installs and runs all of this, documented.

## Principles

- **Compatibility first:** unmodified binaries working, generically; fwe
  MUST NOT special-case anything for one program.
- **The program's code runs as it is:** fwe changes only what macOS
  forces (system calls, thread-pointer accesses and `x18` uses, each one
  instruction branched to a stub); code made at run time runs from
  translations in fwe's code cache ([docs/jit.md](docs/jit.md)).
- **The VM is the last resort:** it is only for a program that cannot run
  in-process, and MUST NOT be used to make one faster.
- **Native speed:** fwe's cost is what the layer adds, held to budgets in
  CI.
- **Work placed explicitly, in fwe or in macOS:** each mechanism either
  does its work in fwe (in the process's memory, or memory every fwe
  process maps) or hands it to macOS (a host call or a host object). Both
  are valid; the mechanism's documentation MUST say which it uses, and its
  tests and benchmarks decided it. What Linux keeps in kernel memory MUST
  stay in memory, not in files on disk.
- **Skip work before speeding it up:** work kept between runs and shared
  between processes, work done only when needed, answers from fwe's own
  caches kept correct against the host. Then what is left is made
  cheaper.
- **Counted, not assumed:** a cause MUST be found by counting and
  reproducing; instrumentation, tests and benchmarks MUST be built before
  the change they judge, and decide which work is done. Work they do not
  justify is listed as not planned, with its numbers.
- **No blockers:** an implementation problem is something to solve; a
  large redesign is planned and done when it is the way forward.

## Measuring progress

- **Workloads:** unmodified distribution binaries run as end-to-end
  tests, their output checked.
- **Conformance:** LTP's system-call tests run in CI against a baseline
  (`tools/ltp`); a test that stops passing fails CI.
- **Performance:** CI benchmarks against native macOS on the same runner,
  with native Linux beside them. Macro benchmarks are real programs at
  work (a JDK, Node.js, LuaJIT, Python, SQLite, git, a C build); micro
  benchmarks isolate one cost (a system call, a fork, a translated call).
  A budget is a ratio to the same work done natively; a figure over its
  budget fails CI.
- **Instrumentation:** fwe counts its own work (`FWE_TIMING`, the
  translator's counts in [docs/jit.md](docs/jit.md#what-it-costs)), and
  the benchmarks profile each workload in CI.

[AGENTS.md](AGENTS.md) describes how work is delivered.
