# Roadmap

The path to the goal in [PLAN.md](PLAN.md): Linux command-line programs,
containers, graphical Linux programs, Windows programs through Wine and
gVisor's sandbox, all on macOS at native speed. The work left is laid out
as pull requests, in order, each delivering one outcome
([AGENTS.md](AGENTS.md#development-process)): a pull request is done when
its **Done when** criteria pass as end-to-end tests and benchmarks in CI,
and a milestone when its pull requests are merged.
[docs/architecture.md](docs/architecture.md#known-limitations) lists the
current limitations in detail.

## Status

| Milestone | State |
|---|---|
| M0 Foundation | Done |
| M1 Core userland | Done |
| M2 Everyday software | Done but for the VM backend's run on real hardware |
| M3 Containers | Done |
| M4 Compatibility | Done: every LTP system-call test that applies passes |
| M5 Release | Done but for the first release (the owner's) |
| M6 Native speed and coverage | Under way |
| M7 Graphical programs and sandboxes | Not started |
| M8 Virtual networking | After 1.0 |

What runs unmodified, with its output checked in CI:
- **Natively, in-process:** Debian's coreutils, bash, git, SQLite,
  lighttpd, rustc with Cargo, apt and Node.js 18; Alpine's Node.js 24,
  LuaJIT, Racket, GNU Guile and OpenJDK, whose JIT compilers' code runs
  from fwe's translations, and Python making code with `eval`.
- **In the VM**, for executables linked below 4 GiB: Debian's Python,
  GCC, clang and Go, and Alpine's SBCL, on the software stand-in for
  Hypervisor.framework only.
- **Containers:** crun, Podman and containerd run the `alpine` image;
  Podman builds images, pushes and pulls them through a registry and runs
  rootless, and Debian's Podman runs in the VM; Docker loads, runs and
  builds images, and Docker Compose brings up a project.
- **Wine:** Alpine's arm64 Wine runs ARM64 Windows console programs in the
  VM (`fwe --vm`), on the stand-in.

## Done

- **M0 — Foundation:** CI on macOS 15 and 26 and Linux; ELF loading;
  system calls trapped; an end-to-end harness. *A static Linux binary
  prints "hello".*
- **M1 — Core userland:** processes and threads, memory, files confined
  to a Linux root filesystem, signals with Linux's frame layout, pipes,
  glibc and musl dynamic linking. *bash and coreutils run from a Debian
  root filesystem.*
- **M2 — Everyday software** (but for the real-hardware run): networking,
  terminals and job control, `epoll` and the descriptor-based event
  calls, `/proc` and `/sys`, virtual credentials, the hypervisor backend
  for executables linked below 4 GiB. *git, compilers, Node, Go, Rust,
  apt, a database and a web server run unmodified.*
- **M3 — Containers:** namespaces, cgroups v2, overlay mounts, seccomp
  and capabilities. *crun, Podman and containerd run standard images.*
- **M4 — Compatibility:** the rest of Linux's call table that macOS can
  carry, ptrace for `strace` and `gdb`, Docker with BuildKit and Compose,
  rootless Podman, Wine's console programs in the VM. *Every LTP
  system-call test that applies passes, the rest listed with their
  reasons in `tools/ltp/exceptions.txt`.*
- **M5 — Release** (but for the first release): benchmarks in CI, the
  system-call gate, user documentation whose recipes CI runs, the
  Homebrew formula, `fwe --pull`, and a release workflow that signs and
  notarizes.

What each Linux mechanism becomes under fwe is in
[linux-on-macos.md](docs/linux-on-macos.md#what-fwe-enforces).

## Left to 1.0

### M2 — finish

- [ ] **The VM backend on real hardware:** the `hv_` tests and
  `fwe --hv-spike` pass in the self-hosted `hypervisor` CI job, on a
  machine whose crash costs nothing, never the development Mac
  ([docs/hypervisor.md](docs/hypervisor.md)). It needs a registered runner
  and the `FWE_HV_SELF_HOSTED` variable set: an owner's action, not code.

**Done when:** the target programs run unmodified, those in the VM on real
hardware.

### M5 — finish

- [ ] **The first release:** the Developer ID secrets and the release
  whose tag the formula names (the owner's actions, not code).

**Done when:** a user installs a release and runs a Debian or Alpine
userland and Podman with it, following the documentation.

### M6 — Native speed and native coverage

Linux code runs at native speed, what fwe adds is held to budgets
([PLAN.md](PLAN.md#principles)), and programs that need the VM run
natively wherever fwe can make them fit the Mac. Speed comes first from
skipping work: work kept between runs and shared between processes, work
done only when something needs it, answers from fwe's own caches where
they stay correct. The VM is never the way to make a program faster.

Done:

- [x] **Benchmark budgets in CI:** the benchmark job fails when a figure
  exceeds its budget. Programs run under fwe as Alpine builds them, on
  realistic workloads (a Lua script, a Python script, SQLite on disk,
  git's commits, history and status, xz), against the same projects
  built natively by Homebrew, both sides' output compared. A program that
  computes is held to fwe's share of its CPU samples (DTrace: all samples
  ÷ those in the program's own code), since its time against Homebrew's
  build also measures the builds' differences; everything else to its
  time against native macOS on the same runner. Each row names the
  backend fwe ran it in; the table adds native Linux on arm64, and
  `tools/bench/vm.sh` a Linux VM and fwe's VM backend on a Mac.

  | Benchmark | Budget |
  |---|---|
  | a system call (`getpid`, `getppid`, `fstat`, `stat`, `open`+`close`, `pread`, `mmap`+`munmap`; one thread and several at once) | 1.5× macOS |
  | thread create and join | 3× macOS |
  | `fork` + exit + wait | 3× macOS |
  | `fork` + `exec` + wait | 3× macOS |
  | start-up | 3× macOS |
  | SQLite on disk, git | 1.5× macOS |
  | building a C project (Lua), a Lua script, a Python script, xz | fwe's share 1.2× |
- [x] **Prepared images kept:** the code fwe prepares in a program and its
  libraries is kept on disk by the file's identity and mapped from there
  the next time, as Rosetta 2 keeps its translations: prepared once, its
  pages the host's cached ones, shared and never copied.
- [x] **Executables linked below 4 GiB:** macOS keeps the low 4 GiB from
  every arm64 process, so such an executable runs natively only moved
  above it. A static one whose link kept its relocations
  (`--emit-relocs`) is moved by a multiple of 4 GiB, its absolute
  addresses relocated, and runs natively. One linked without them (as
  every non-PIE program the distributions ship is:
  [which ones](docs/linux-on-macos.md#how-distributions-build-their-programs)),
  linked dynamically, or holding an address no relocation follows runs
  in the VM, and `--strace` says why.
- [x] **Code made at run time, by translation:** code a program makes
  executable as it runs (JIT compilers' code, self-modifying code, code
  on the stack) runs from translations in fwe's code cache, the
  program's memory never executable on the host and never changed: its
  `x18` uses expanded in the translation, the program's flush of the
  code it changed (`ic ivau`, through any mapping) dropping the
  translations, a fault or signal delivered at the program's own
  instruction ([docs/jit.md](docs/jit.md)). Tested with Node.js 18 and
  24, LuaJIT, Racket, Guile, Python's `eval`, OpenJDK, quines, IOCCC
  winners and self-modifying programs.
- [x] **Where the translator's time goes, counted:** `FWE_TIMING` and the
  benchmarks' report count, per workload, the blocks made by where their
  code comes from (a file, or generated), those whose address and words
  a run made before, entries made with the program's own `x16` and
  `x17` and those entered, blocks made ahead and those run, calls from
  translated code into a library's, and the time making each block; and
  micro benchmarks of translated code against the same code run from the
  program's file (calls and returns, indirect branches, a loop, many
  small functions in random order, a function made and run).
- [x] **Translations of a file's code kept:** the blocks made from a
  file's code (a runtime's library, the C library, the program's own)
  kept on disk by the file's identity and where it is loaded, as prepared
  images are kept, and taken by a later process, or this one, that comes
  to the same code; a block is taken only where the program's words are
  as it was made from, so a stale one never runs.
- [x] **A JDK at work:** Alpine's OpenJDK (a JIT runtime: code it writes
  and runs, many threads, a garbage collector) runs natively under fwe,
  and the benchmarks run a realistic workload on it (compiling and running
  a multi-threaded application) against Homebrew's OpenJDK of the same
  release on the same runner, their output compared, within 1.5×.

Left, as pull requests in order. Each brings the instrumentation that
shows where its time goes, micro benchmarks that isolate the costs it
attacks and macro benchmarks of programs at work, all in CI; counts
decide which work is skipped before any is built.

#### PR 1 — Translated code at native speed

- [ ] **Traces:** chains of blocks the program runs hot made again as one
  straight run of code, their cold paths out of line, dropped with any
  block they hold.
- [ ] **Inline caches:** a `br`, `blr` or `ret` first compares its target
  with the one last taken there and branches straight to its
  translation, the table looked up only when they differ.
- [ ] **Cheaper blocks:** what each word stands for written in its
  compact form directly, with no larger form made first.
- [ ] **Generated code's translations kept:** a block made from
  generated code kept by its address and words, and taken by a later run
  that writes the same words there.
- [ ] **Blocks made only when needed:** a block's entry with the
  program's own `x16` and `x17` made on its first use, not with every
  block; blocks made ahead of the program only as far as the counts show
  they are run.
- [ ] **Macro benchmarks of JIT runtimes:** Node.js and LuaJIT at work
  against Homebrew's builds on the same runner, their output compared.

**Done when:** the micro benchmarks of translated code hold 1.3× of the
same code run from the program's file; Node.js's and LuaJIT's benchmarks
1.5×; and a second run of a JIT runtime's workload takes, rather than
makes, the blocks of generated code the first made at the same address
from the same words.

#### PR 2 — Generated code run as it is, where it is sound

Decided by counts from the JDK, Node.js and LuaJIT workloads, each
adopted only where it saves more than it costs, otherwise listed under
[Not planned](#not-planned-for-10) with the numbers:

- [ ] **Clean pages run natively:** a page of generated code none of
  whose words is a system call, a thread-pointer access or a use of `x18`
  runs as it is, translated again once written (the counts: such pages'
  share of the time, and how often they are written).
- [ ] **A library's code run natively when generated code calls it:** its
  return into generated code taken as a fetch (the counts: calls from
  translated code into a library against the work done there).

**Done when:** each item is adopted with its benchmarks holding their
budgets, or listed as not planned with the counts that decided it.

#### PR 3 — File lookups without the host

- [ ] **Counted:** the benchmarks' report counts path lookups by kind
  (found, absent, in a container image's layers) and host calls per
  guest call.
- [ ] **Image layers cached:** names, links and attributes in a
  container image's read-only layers (an overlay's lower layers, which
  Linux too requires unchanged) kept in memory every fwe process shares.
- [ ] **Directories cached, kept correct by the host:** the names a
  directory holds, absent ones included, cached and checked before use
  against a kqueue watch of the directory, which the host posts during
  the call that changes it; adopted if a check costs well under a lookup.
- [ ] **Descriptors opened when used:** an `O_PATH` descriptor opens the
  host file only when a call needs it.
- [ ] **`open` and `close` at the host's cost:** fwe's bookkeeping per
  descriptor made when something asks for it.
- [ ] **Benchmarks:** micro: a lookup of an absent name, a `stat` in an
  image's layer, `open`+`close`; macro: Python's start-up (its import
  search), `git status` in a large tree, a command started in a
  container.

**Done when:** a `stat` in an image's layer and a lookup of an absent name
in a directory looked at before each hold 0.5× macOS (or the directory
cache is listed as not planned with its counts), and `open`+`close` holds
1.1× macOS.

#### PR 4 — `fork` and signals

- [ ] **Fewer mappings to fork:** fwe's code cache, translation tables
  and descriptor room made on first use, in as few host regions as they
  can be; the benchmarks report a process's host mappings.
- [ ] **A signal handler's return without a host signal:** `rt_sigreturn`
  through the gate.

**Done when:** `fork` + exit + wait holds 2× macOS (from 3×) and a handled
`SIGSEGV` 2× macOS (now without a budget).

#### PR 5 — 4 KiB pages natively

- [ ] **4 KiB pages natively:** `mmap`, `mprotect` and `munmap` at 4 KiB
  granularity on the Mac's 16 KiB pages: file contents at 4 KiB offsets
  copied in, each host page given the union of its parts' protections and
  the stricter parts enforced by fwe (a write to a read-only part caught
  and delivered as Linux would), and 4096 in `AT_PAGESZ` for a program
  that needs it. A layout that cannot be kept so (an execute-only part
  beside a writable one in one host page, say) sends the program to the
  VM.
- [ ] **Benchmarks:** micro: `mmap`, `mprotect` and `munmap` of 4 KiB
  parts, and a write caught in a read-only part.

**Done when:** a program that needs 4 KiB pages runs natively in CI, its
calls hold the system-call budget, and what still needs the VM for its
pages is listed with the reason.

#### PR 6 — Wine natively

- [ ] **Wine natively:** Windows' ARM64 code keeps the thread's TEB in
  `x18`, which macOS clears, so code Wine maps executable is prepared as a
  program's own is, with its `x18` uses rewritten; its images' 4 KiB
  sections are mapped as above. Wine then runs Windows console programs
  without `fwe --vm`, and the benchmarks run it at work: Windows programs
  built for ARM64 (a script interpreter, a database, compression) under
  Alpine's Wine on fwe, against the same sources built natively for macOS
  on the same runner, their output compared, within 1.5×.

**Done when:** Wine's test program runs natively in CI and its benchmarks
hold 1.5×.

**M6 is done when** these pull requests are merged: the budgets hold in
CI; a low-linked executable whose link kept its relocations, the JIT
runtimes and programs above, and Wine's test program run natively in CI;
and what still needs the VM is listed with the reason.

### M7 — Graphical programs and sandboxes

Linux programs with windows on the Mac's screen, Windows programs through
Wine with theirs, and a Linux program inside gVisor, all on fwe. CI starts
an X server and drives each program with synthetic input (keys, clicks, a
page loaded, a file edited), checking what it draws by the server's
screenshot.

#### PR 1 — A display

- [ ] **A display for Linux programs:** X11 clients drawn by an X server
  on the Mac (XQuartz), reached through the socket `DISPLAY` names, with
  shared memory (`MIT-SHM`) where the server offers it; Wayland clients
  through a compositor that speaks to the Mac, if one proves practical.
- [ ] **Demo programs:** `xterm`, `xeyes`, `xclock`, GTK's and Qt's demo
  programs.
- [ ] **Benchmarks:** micro: a window's frame drawn through shared memory,
  and an X request's round trip; macro: a demo program's frames per
  second against the same program on Linux.

**Done when:** `xterm`, `xeyes`, `xclock` and GTK's and Qt's demo
programs run under fwe in CI, driven and checked by what they draw.

#### PR 2 — The GPU

- [ ] **GPU acceleration:** a Linux GPU device (`/dev/dri/renderD128`)
  that fwe provides, speaking virtio-gpu's interface to Mesa's Venus
  Vulkan driver, whose commands fwe runs on the Mac's GPU through
  virglrenderer and MoltenVK (Vulkan on Metal), in-process, as libkrun
  does for its VMs; OpenGL through Mesa's Zink (OpenGL on Vulkan), and
  Direct3D under Wine through DXVK and VKD3D-Proton (Direct3D on
  Vulkan). Frames reach the X server as images in shared memory.
- [ ] **GPU demo programs:** `glxgears` and `vkcube`.
- [ ] **Benchmarks:** micro: a Vulkan command buffer submitted and a
  frame presented; macro: `vkcube`'s frame rate against MoltenVK's
  natively on the same runner.

**Done when:** `glxgears` and `vkcube` draw on the GPU, as their renderer
names it, and `vkcube`'s frame rate holds 1.5× of MoltenVK's natively.

#### PR 3 — Browsers and application frameworks

- [ ] **Browsers:** Chrome (Google's Linux arm64 build, or Chromium where
  none is published) and Firefox, with their sandboxes on and their
  content, GPU and network processes, browsing local pages and playing
  video.
- [ ] **Application frameworks:** an Electron app (Electron's quick-start
  and Visual Studio Code); Zed, the editor (Vulkan); a Tauri app (Rust,
  WebKitGTK); a Wails app (Go, WebKitGTK); a tkinter app (Python, Tk).
- [ ] **Benchmarks:** a page loaded and a video's frames played against
  the same browser natively on macOS; an Electron app's start-up.

**Done when:** the browsers, Zed and the framework apps above run in CI
on the GPU, driven and checked by what they draw.

#### PR 4 — Graphical Wine

- [ ] **Graphical Wine:** Windows programs with windows through Wine's
  X11 driver, natively (M6's Wine item): Wine's own (Notepad,
  Minesweeper, `regedit`) and a Direct3D demo.

**Done when:** Wine's own programs and the Direct3D demo draw in CI, the
demo on the GPU.

#### PR 5 — gVisor on fwe

- [ ] **gVisor on fwe:** `runsc` running a Linux program on its `systrap`
  platform (`seccomp`'s `SECCOMP_RET_TRAP`, `SIGSYS` and memory shared
  between its sentry and stub processes) or its `ptrace` platform, as
  Podman or Docker start it. The program is a realistic JDK workload
  (OpenJDK compiling and running a multi-threaded application:
  collections, streams, JSON, garbage collection), benchmarked under
  `runsc` on fwe against the same workload under `runsc` on Linux, its
  output compared.

**Done when:** CI runs the JDK workload through `runsc` on fwe, its
benchmark beside `runsc` on Linux.

## After 1.0

### M8 — Virtual networking

Multi-process and multi-container Linux applications on networks of their
own, as on a Linux host, with the host's TCP/IP stack carrying the
traffic at native speed.

#### PR 1 — Addresses per network namespace

- [ ] **Addresses per network namespace:** veth pairs and bridges as fwe's
  records, with the interfaces, addresses and routes netlink shows and
  sets; a socket bound or connected to a namespace's address is mapped to
  a host endpoint (a loopback port or a Unix socket) through a table all
  fwe processes share, with `connect`, `accept`, `getsockname` and
  `getpeername` translated, so no packet passes through fwe.
- [ ] **Benchmarks:** micro: a connection's set-up and a round trip
  between two namespaces, against loopback natively; macro: an HTTP
  server's throughput between two containers.

**Done when:** two network namespaces reach each other by address
through veth pairs and a bridge, at the host's loopback speed within
1.5×.

#### PR 2 — Container networks

- [ ] **Container networks:** Podman's netavark and Docker's bridge driver
  set them up through those calls; containers reach each other by address
  and by name (aardvark-dns and Docker's embedded resolver, which run as
  Linux programs); published ports listen on the Mac; outgoing
  connections leave as the Mac's, which is network address translation by
  construction.
- [ ] **A server process, only if needed:** for what must outlive every
  process of a network (a published port whose creator has ended), a
  per-user fwe process started on demand, as Wine's `wineserver` is.

Packet-level features (iptables and nftables rules, packet sockets,
TUN) would need a TCP/IP stack inside fwe, as gVisor has, which every
packet would pass through; they stay out unless one proves cheap enough
for the native-speed principle.

**Done when:** Docker Compose with a bridge network (a web application, a
database and a cache) and a Podman pod run, their containers reaching
each other by name, with a published port reachable from the Mac.

## Not planned for 1.0

Calls for these are refused (`ENOSYS`, `EINVAL` or `EPERM`) unless noted,
so programs that probe for them fall back.
- **io_uring:** programs fall back to ordinary system calls.
- **Networking beyond loopback and the host's sockets** (veth, bridges,
  firewalling, packet sockets, SCTP, RDS, TUN, kernel TLS): a new
  network namespace has loopback only; other families fail with
  `EAFNOSUPPORT`, other protocols with `EPROTONOSUPPORT`, kernel TLS
  with `ENOPROTOOPT`. Raw IP sockets take `CAP_NET_RAW` and, on the host,
  fwe running as root; ping sockets follow `net.ipv4.ping_group_range`.
  Addresses per namespace, bridges and container networks come after 1.0
  (M8).
- **Chosen pids in the initial pid namespace** (`clone3`'s `set_tid`
  there): pids are the host's, which macOS assigns; `set_tid` chooses
  them in fwe's own pid namespaces, as `/proc/sys/kernel/ns_last_pid`
  does, which in the initial namespace is only read.
- **`fanotify`:** its permission events would hold every process's file
  calls on another's answer; programs fall back to inotify.
- **A shared descriptor table without shared memory** (`CLONE_FILES`
  without `CLONE_VM`): two macOS processes cannot share one, so the child
  gets a copy.
- **Pipes over 64 KiB:** a host pipe holds no more, so a pipe starts at
  64 KiB, not Linux's 256 KiB with 16 KiB pages.
- **Setting the clock, and time namespaces:** fwe's root lacks
  `CAP_SYS_TIME`, as in a container; the Mac's clock is only read, and
  `CLONE_NEWTIME` fails with `EINVAL`.
- **Disk filesystems and block devices** (ext4, XFS, btrfs, quotas,
  fs-verity, RAM disks, SCSI): files are the host's, on its filesystem;
  fwe mounts tmpfs, proc, sysfs, cgroup2, devpts, mqueue and overlay, and
  its loop devices hold no filesystem.
- **Swap, huge pages and memory error injection** (but `MADV_HWPOISON`,
  which natively makes the pages fault): the host manages memory;
  `swapon` fails with `ENOSYS`, as on a kernel without swap, and the huge
  page pool is empty (`ENOMEM` for what reserves from it).
- **cgroup resource limits but `pids.max`** (memory, CPU, I/O): accepted,
  not enforced; the host shares its resources alike.
- **Per-process I/O counts** (`/proc/<pid>/io`'s `rchar`, `syscr` and
  the like): the host counts only storage bytes per process.
- **perf events:** `perf_event_open` fails with `ENOSYS`.
- **userfaultfd:** a fault handed to another thread to resolve would have
  fwe block the faulting thread in its signal handler, natively and in the
  VM; few programs use it (CRIU, QEMU's post-copy migration).
  `userfaultfd` fails with `ENOSYS`, and there is no `/dev/userfaultfd`.
- **Setting the initial UTS namespace's names:** they are the Mac's; a new
  UTS namespace's are the guest's to set.
- **CPU affinity:** macOS has none; `sched_setaffinity` is accepted and
  pins nothing.
- **x86_64 Linux binaries, and x86 and x64 Windows programs under Wine:**
  fwe runs arm64 code natively and emulates no other architecture; Windows
  x86 code would need an x86 emulator (FEX or box64).
- **kselftests and gVisor's system-call suite as gates:** LTP is the
  conformance gate.
