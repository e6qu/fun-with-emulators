# Plan

## Goal

A practical, performant and fully compatible Linux environment on macOS
(Apple Silicon), without a Linux kernel. Unmodified Linux arm64 programs
run on it: command-line programs and toolchains, container engines
(Docker, Podman, containerd) and their images, graphical Linux programs,
Windows programs (console and graphical) through Linux's Wine, and
sandboxes such as gVisor, faster than in a Linux VM on the same Mac, the
alternative fwe competes with. fwe is written in Rust.

## Approach

fwe implements the Linux user-space ABI on top of macOS, as Wine
implements Windows' and WSL1 implemented Linux's on Windows. A Linux
program's instructions run directly on the CPU inside an `fwe` process;
its system calls go to fwe's kernel layer, which provides Linux's
processes, threads, memory, files, signals, networking, namespaces and
cgroups on macOS, with fwe's own `/proc`, `/sys` and `/dev`.

Two backends share that kernel layer:
- **Native**, in-process, for every position-independent binary, which
  is what distributions ship.
- **Hypervisor**, for executables linked into the low 4 GiB that macOS
  reserves in every arm64 process, and for programs that need 4 KiB
  pages: a minimal Hypervisor.framework VM gives the program an address
  space of its own. It provides CPU and memory only; no Linux kernel runs
  in it.

A VM running a Linux kernel is a non-goal.
[docs/architecture.md](docs/architecture.md) describes how each part works.

## Scope

In scope:
- the Linux user-space ABI on arm64: system calls, ELF loading, signals,
  `/proc`, `/sys`, `/dev`, ioctls, namespaces and cgroups;
- distributions' userlands (Debian, Alpine);
- container engines and standard images;
- gVisor's sandbox (`runsc`) running on fwe;
- Wine, for ARM64 Windows programs, console and graphical;
- graphical Linux programs, drawn by an X server on the Mac, with
  OpenGL and Vulkan on the Mac's GPU.

Out of scope:
- kernel modules and private kernel interfaces;
- hardware drivers;
- x86 binaries (Linux or Windows).

## The finish line: 1.0

1.0 is reached when all of these hold, as [ROADMAP.md](ROADMAP.md)
defines them:
- the target programs (git, compilers, Node, Go, Rust, apt, a database, a
  web server, a JDK) run unmodified, those in the VM on real hardware;
- Docker, Podman and containerd build and run images, rootless Podman
  included;
- every LTP system-call test passes, except those for what is not planned
  for 1.0 and those that fail or skip on Linux too with the same build,
  each listed with its reason;
- `strace` and `gdb` work on a guest program;
- Linux code runs at native speed, what fwe adds stays within the
  benchmark budgets, and as much runs natively as the host allows
  (executables linked below 4 GiB and programs that need 4 KiB pages,
  Wine among them);
- graphical Linux programs, and Windows console and graphical programs
  through Wine, run and draw on the Mac's screen, on its GPU;
- a JDK workload runs inside gVisor (`runsc`) on fwe;
- a signed release installs and runs all of this, with user
  documentation.

What 1.0 leaves out is listed under "Not planned for 1.0" in the roadmap.

## After 1.0

Virtual networking (M8): multi-process and multi-container applications
on networks of their own, with addresses per network namespace, bridges,
named container networks and ports published on the Mac. The host's
TCP/IP stack carries the traffic; a server process is added only for what
must outlive every process of a network.

## Principles

- **Compatibility first:** success is unmodified Linux binaries working.
- **Wine's and WSL1's mechanisms, mutatis mutandis:** the program's
  machine code runs unchanged, in-process, except for the minimal
  rewrites macOS forces: system calls, thread-pointer accesses and `x18`
  uses, each one instruction turned into a branch to a stub. No VM is used
  where one is not needed.
- **Native speed:** fwe's cost is judged by what the layer adds. No
  abstraction of fwe's may put a cost in the program's own code. What fwe
  adds at system calls, process and thread creation, start-up and in
  programs at work is held to budgets measured in CI. A design that slows
  guest code (a packet-level network stack, instrumenting every block) is
  chosen only where nothing cheaper gives the behaviour.
- **Caching and translation where sound:** work can be kept between runs
  (prepared images, as Rosetta 2 keeps its translations), and
  Rosetta-style binary translation is allowed where it is feasible and
  sound.
- **No blockers:** an implementation problem is something to solve.
- **Measured progress:** real workloads and LTP define what "working"
  means.

## Measuring progress

- **Workloads:** unmodified distribution binaries run as end-to-end tests
  with their output checked.
- **Conformance:** LTP's system-call tests run in CI against a baseline of
  those that pass (`tools/ltp`); a test that stops passing fails CI.
- **Performance:** benchmarks against native macOS (on the same runner),
  native Linux on arm64, a Linux VM on the same Mac and fwe's own VM
  backend, each row naming the backend fwe ran it in; CI holds fwe to
  budgets (M6), and `tools/bench/vm.sh` adds the VM columns on a Mac.

[AGENTS.md](AGENTS.md) describes how work is delivered.
