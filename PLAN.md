# Plan

## Goal

A practical, performant and compatible Linux environment on macOS (Apple
Silicon), without a Linux kernel and faster than a Linux VM on the same
Mac. Unmodified Linux arm64 programs run on it: command-line programs and
toolchains, language runtimes and their JIT compilers, container engines
(Docker, Podman, containerd) and their images, graphical Linux programs,
Windows programs through Linux's Wine, and gVisor's sandbox. fwe is
written in Rust.

## Approach

fwe implements the Linux user-space ABI on macOS, as Wine implements
Windows' and WSL1 implemented Linux's on Windows. A Linux program's code
runs directly on the CPU inside an `fwe` process; its system calls go to
fwe's kernel layer, which provides Linux's processes, threads, memory,
files, signals, networking, namespaces and cgroups, with fwe's own
`/proc`, `/sys` and `/dev`.

Two backends share that kernel layer:
- **Native**, in-process, for every position-independent binary (what
  distributions ship) and for executables whose link kept their
  relocations, moved above the 4 GiB macOS reserves.
- **Hypervisor**, for the other executables linked below 4 GiB and for
  programs that need 4 KiB pages: a minimal Hypervisor.framework VM gives
  the program an address space of its own. It provides CPU and memory
  only; no Linux kernel runs in it.

A VM running a Linux kernel is a non-goal.
[docs/architecture.md](docs/architecture.md) describes how each part
works.

## Scope

In scope:
- the Linux user-space ABI on arm64: system calls, ELF loading, signals,
  `/proc`, `/sys`, `/dev`, ioctls, namespaces and cgroups;
- distributions' userlands (Debian, Alpine);
- container engines and standard images;
- gVisor's sandbox (`runsc`) on fwe;
- Wine, for ARM64 Windows programs, console and graphical;
- graphical Linux programs, drawn by an X server on the Mac, with OpenGL
  and Vulkan on the Mac's GPU.

Out of scope: kernel modules and private kernel interfaces, hardware
drivers, and x86 binaries (Linux or Windows).

## The finish line: 1.0

1.0 is reached when all of these hold, as [ROADMAP.md](ROADMAP.md)
defines them:
- the target programs (git, compilers, Node, Go, Rust, apt, a database, a
  web server, a JDK) run unmodified, those in the VM on real hardware;
- Docker, Podman and containerd build and run images, rootless Podman
  included;
- every LTP system-call test passes, except those for what is not planned
  for 1.0 and those that fail or skip on Linux too, each listed with its
  reason;
- `strace` and `gdb` work on a guest program;
- Linux code runs at native speed, what fwe adds stays within the
  benchmark budgets, and as much runs natively as the host allows;
- graphical Linux programs, and Windows programs through Wine, run and
  draw on the Mac's screen, on its GPU;
- a JDK workload runs inside gVisor (`runsc`) on fwe;
- a signed release installs and runs all of this, with user
  documentation.

What 1.0 leaves out, and what comes after it (virtual networking), is in
the roadmap.

## Principles

- **Compatibility first:** success is unmodified Linux binaries working,
  generically: no mechanism special-cased for one program.
- **The program's code runs as it is, in-process:** fwe changes only what
  macOS forces (system calls, thread-pointer accesses and `x18` uses,
  each one instruction branched to a stub), and code a program makes at
  run time runs from translations in fwe's code cache, its own memory
  untouched. No VM is used where one is not needed.
- **Native speed:** fwe's cost is what the layer adds; no abstraction of
  fwe's may put a cost in the program's own code. What fwe adds at system
  calls, process and thread creation, start-up and in programs at work is
  held to budgets in CI. Work may be kept between runs (prepared images,
  as Rosetta 2 keeps its translations).
- **No blockers:** an implementation problem is something to solve.
- **Measured progress:** real workloads, LTP and the benchmarks define
  what "working" means.

## Measuring progress

- **Workloads:** unmodified distribution binaries run as end-to-end tests
  with their output checked.
- **Conformance:** LTP's system-call tests run in CI against a baseline
  (`tools/ltp`); a test that stops passing fails CI.
- **Performance:** benchmarks in CI against native macOS on the same
  runner, with native Linux on arm64 beside them, and a Linux VM and fwe's
  VM backend from `tools/bench/vm.sh` on a Mac; a figure over its budget
  fails CI.

[AGENTS.md](AGENTS.md) describes how work is delivered.
