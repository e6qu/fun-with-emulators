# Roadmap

The path to the goal in [PLAN.md](PLAN.md): Linux command-line programs,
containers, graphical Linux programs, Windows programs through Wine and
gVisor's sandbox, all on macOS at native speed. A milestone is done when
its **Done when** criteria pass as end-to-end tests in CI.
[docs/architecture.md](docs/architecture.md#known-limitations) lists the
current limitations in detail.

## Status

| Milestone | State |
|---|---|
| M0 Foundation | Done |
| M1 Core userland | Done |
| M2 Everyday software | Done but for the VM backend's run on real hardware |
| M3 Containers | Done |
| M4 Compatibility | Done: all 1213 of LTP's system-call tests that apply pass (1551 run) |
| M5 Release | Done but for the first release (the owner's) |
| M6 Native speed and coverage | Under way |
| M7 Graphical programs and sandboxes | Not started |
| M8 Virtual networking | After 1.0 |

What runs unmodified, with its output checked in CI:
- **Natively, in-process:** Debian's coreutils, bash, git, SQLite, lighttpd,
  Node.js (V8's JIT), rustc with Cargo, and apt.
- **In the VM**, for executables linked below 4 GiB: Debian's Python, GCC,
  clang and Go, on the software stand-in for Hypervisor.framework only.
- **Containers:** crun, Podman and containerd run the `alpine` image;
  Podman builds images, pushes and pulls them through a registry and runs
  rootless, and Debian's Podman runs in the VM; Docker loads, runs and
  builds images, and Docker Compose brings up a project.
- **Wine:** Alpine's arm64 Wine runs ARM64 Windows console programs in the
  VM (`fwe --vm`), on the stand-in.

## Done

**M0 — Foundation.** CI on macOS 15 and 26 plus a Linux unit-test job; ELF
loading; system calls trapped by rewriting `svc #0`; an end-to-end harness
of assembly and Rust guests. *A static Linux binary prints "hello".*

**M1 — Core userland.** Processes and threads (`clone`, futexes, `fork`,
`execve`, `wait4`), memory, files confined to a Linux root filesystem,
signals with Linux's frame layout, pipes, rewriting of `svc`, `TPIDR_EL0`
and `x18`, and glibc and musl dynamic linking. *bash and coreutils run from
a Debian rootfs.*

**M2 — Everyday software**, but for the real-hardware run. Networking (TCP,
UDP, IPv4, IPv6, `AF_UNIX` with descriptor passing); terminals, ptys and
job control; `epoll`, `eventfd`, `timerfd`, `signalfd`; the `/proc` and
`/sys` files programs read; virtual credentials; signals between processes
and threads; `vfork`, `posix_spawn`, `execveat`, `clone3`; `EFAULT` for
bad pointers; fwe's own descriptors out of the guest's reach; the
hypervisor backend for executables linked below 4 GiB, with threads,
`fork`, `vfork`, `execve` in both directions, pointer authentication and
BTI. *The target programs (git, compilers, Node, Go, Rust, apt, a
database, a web server) run unmodified.*

**M3 — Containers.** Mount, pid, user, UTS, IPC, network and cgroup
namespaces; cgroups v2 with device programs; overlay mounts; seccomp and
capabilities. *crun, Podman and containerd run standard images.*

**M4 — Compatibility.** Every LTP system-call test that applies passes in
CI, the rest listed with their reasons in `tools/ltp/exceptions.txt`;
ptrace serves Alpine's `strace` and `gdb`; Docker Engine with BuildKit and
Compose, and Podman building, pushing, pulling and running rootless (and
Debian's in the VM); Wine runs ARM64 Windows console programs under
`fwe --vm`; the rare `x18` forms are rewritten, and a binary without
section headers has its unwind table found through `PT_GNU_EH_FRAME`.
*Each is tested end to end in CI.* Beyond M3 it brought process
descriptors, real-time and cross-process signals, ptrace, POSIX timers,
resource limits and scheduling; Linux's memory calls; the file calls
(`openat2`, `O_TMPFILE`, file handles, leases, OFD locks, splice, inotify,
AIO); the new mount API and propagation; System V IPC, message queues,
keyrings, eBPF maps and socket filters; and the rest of Linux's call
table that macOS can carry. What each Linux mechanism becomes under fwe
is in
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

### M5 — Release

- [x] **Performance:** benchmarks in CI of start-up, system-call cost (one
  thread and several at once), `fork`/`exec` and a C project's build,
  against native macOS and Linux on arm64; system calls through a direct
  gate rather than a trap; a kernel lock whose reading calls run side by
  side.
- [ ] **Packaging:** a signed and notarized `fwe` with the hypervisor
  entitlement, a Homebrew formula, and a command that fetches and unpacks
  a Debian or Alpine root filesystem. In place: `fwe --pull` (CI pulls and
  runs Alpine's and Debian's images), the formula (`Formula/fwe.rb`, which
  CI installs and tests from source), and the release workflow, which
  signs under the hardened runtime and notarizes with a Developer ID.
  Left: the Developer ID secrets and the first release, whose tag the
  formula names (the owner's actions, not code).
- [x] **User documentation:** installing, running programs and containers,
  and what is not supported ([docs/user-guide.md](docs/user-guide.md),
  whose recipes CI runs as written).

**Done when:** a user installs a release and runs a Debian or Alpine
userland and Podman with it, following the documentation.

### M6 — Native speed and native coverage

Linux code runs at native speed, what fwe adds is held to budgets
([PLAN.md](PLAN.md#principles)), and programs that need the VM run
natively wherever fwe can make them fit the Mac.

- [x] **Benchmark budgets in CI:** the benchmark job fails when a figure
  exceeds its budget; the job summary shows each run's figures. Programs
  run under fwe as Alpine builds them, on realistic workloads (a Lua
  script, a Python script, an SQLite database on disk, a git repository's
  commits, history and status, xz compressing and decompressing), and
  natively as Homebrew builds the same projects (the C build with
  Homebrew's clang of the release Alpine's root has); both sides' output
  must match.
  - **Programs that compute** (building Lua, sampled by one compile; the
    Lua script, the Python script, xz):
    the budget applies to fwe's share, from CPU sampling (DTrace) in the
    same run: all samples ÷ samples in the program's own code. fwe's are
    those in fwe, the macOS libraries it calls, its stubs (which carry a
    memory tag of fwe's) and anything unplaced; the macOS kernel's time
    counts as the program's. Their time against Homebrew's builds stays in the
    table as information, since it also measures the builds' differences
    (compiler, C library).
  - **Everything else** keeps its budget against native macOS on the same
    runner.
  - Each row names the backend fwe ran its programs in (from fwe's own
    `backend:` marks), and the table adds native Linux on arm64 (another
    machine), and, from `tools/bench/vm.sh` on a Mac, a Linux VM on that
    Mac and fwe's VM backend (`fwe --vm`), the alternatives fwe competes
    with.

  | Benchmark | Budget |
  |---|---|
  | a system call (`getpid`, `getppid`, `fstat`, `stat`, `open`+`close`, `pread`, `mmap`+`munmap`; one thread and several at once) | 1.5× macOS |
  | thread create and join | 3× macOS |
  | `fork` + exit + wait | 3× macOS |
  | `fork` + `exec` + wait | 3× macOS |
  | start-up | 3× macOS |
  | SQLite on disk, git | 1.5× macOS |
  | building a C project (Lua), a Lua script, a Python script, xz | fwe's share 1.2× |
- [x] **Prepared images kept:** the code fwe prepares in a program (its
  system calls, thread-pointer accesses and `x18` uses rewritten) is kept
  on disk whole, by the file's identity, and mapped from there the next
  time, as Rosetta 2 keeps its translations: the program and its dynamic
  linker as fwe loads them, and each library's code as the dynamic linker
  maps it. A program is prepared once rather than at every start, and its
  code pages are the host's cached ones, shared and never copied
  ([architecture](docs/architecture.md)).
- [x] **Executables linked below 4 GiB:** macOS keeps the low 4 GiB from
  every arm64 process (a smaller `__PAGEZERO` is killed at exec), so such
  an executable runs natively only moved above it. arm64 code reaches its
  own code and data PC-relatively, so moving a whole static image by a
  multiple of 4 GiB keeps its code right; what changes is each absolute
  address it holds, which a link that kept its relocations
  (`--emit-relocs`) lists: those executables are moved and run natively.
  One linked without them (Debian's `python3`, GCC, clang, static Go
  programs: their data holds absolute pointers nothing lists), linked
  dynamically (its dynamic linker relocates it at its link address), or
  holding an address no relocation follows, runs in the VM, and
  `--strace` says why.
- [ ] **A JDK at work:** Alpine's OpenJDK (a JIT runtime: code it writes
  and runs, many threads, a garbage collector) runs natively under fwe,
  and the benchmarks run a realistic workload on it (compiling and running
  a multi-threaded application) against Homebrew's OpenJDK of the same
  release on the same runner, their output compared, within 1.5×.
- [ ] **4 KiB pages natively:** `mmap`, `mprotect` and `munmap` at 4 KiB
  granularity on the Mac's 16 KiB pages: file contents at 4 KiB offsets
  copied in, each host page given the union of its parts' protections and
  the stricter parts enforced by fwe (a write to a read-only part caught
  and delivered as Linux would), and 4096 in `AT_PAGESZ` for a program
  that needs it. A layout that cannot be kept so (an execute-only part
  beside a writable one in one host page, say) sends the program to the
  VM.
- [ ] **Wine natively:** Windows' ARM64 code keeps the thread's TEB in
  `x18`, which macOS clears, so code Wine maps executable is prepared as a
  program's own is, with its `x18` uses rewritten; its images' 4 KiB
  sections are mapped as above. Wine then runs Windows console programs
  without `fwe --vm`, and the benchmarks run it at work: Windows programs
  built for ARM64 (a script interpreter, a database, compression) under
  Alpine's Wine on fwe, against the same sources built natively for macOS
  on the same runner, their output compared, within 1.5×.

**Done when:** the budgets hold in CI; a low-linked executable whose link
kept its relocations, and Wine's test program, run natively in CI; the
JDK's and Wine's benchmarks hold their budgets; and what still needs the
VM is listed with the reason.

### M7 — Graphical programs and sandboxes

Linux programs with windows on the Mac's screen, Windows programs through
Wine with theirs, and a Linux program inside gVisor, all on fwe.

- [ ] **A display for Linux programs:** X11 clients drawn by an X server
  on the Mac (XQuartz), reached through the socket `DISPLAY` names, with
  shared memory (`MIT-SHM`) where the server offers it; Wayland clients
  through a compositor that speaks to the Mac, if one proves practical.
- [ ] **GPU acceleration:** a Linux GPU device (`/dev/dri/renderD128`)
  that fwe provides, speaking virtio-gpu's interface to Mesa's Venus
  Vulkan driver, whose commands fwe runs on the Mac's GPU through
  virglrenderer and MoltenVK (Vulkan on Metal), in-process, as libkrun
  does for its VMs; OpenGL through Mesa's Zink (OpenGL on Vulkan), and
  Direct3D under Wine through DXVK and VKD3D-Proton (Direct3D on
  Vulkan). Frames reach the X server as images in shared memory.
- [ ] **Demo programs:** `xterm`, `xeyes`, `xclock`, `glxgears`, `vkcube`,
  GTK's and Qt's demo programs.
- [ ] **Browsers:** Chrome (Google's Linux arm64 build, or Chromium where
  none is published) and Firefox, with their sandboxes on and their
  content, GPU and network processes, browsing local pages and playing
  video.
- [ ] **Application frameworks:** an Electron app (Electron's quick-start
  and Visual Studio Code); Zed, the editor (Vulkan); a Tauri app (Rust,
  WebKitGTK); a Wails app (Go, WebKitGTK); a tkinter app (Python, Tk).
- [ ] **Graphical Wine:** Windows programs with windows through Wine's
  X11 driver, natively (M6's Wine item): Wine's own (Notepad,
  Minesweeper, `regedit`) and a Direct3D demo.
- [ ] **gVisor on fwe:** `runsc` running a Linux program on its `systrap`
  platform (`seccomp`'s `SECCOMP_RET_TRAP`, `SIGSYS` and memory shared
  between its sentry and stub processes) or its `ptrace` platform, as
  Podman or Docker start it. The program is a realistic JDK workload
  (OpenJDK compiling and running a multi-threaded application:
  collections, streams, JSON, garbage collection), benchmarked under
  `runsc` on fwe against the same workload under `runsc` on Linux, its
  output compared.

**Done when:** CI starts an X server and runs every program above under
fwe, each driven by synthetic input (keys, clicks, a page loaded, a file
edited) and checked by what it draws (the server's screenshot compared),
the GPU programs (`glxgears`, `vkcube`, the browsers, Zed, the Direct3D
demo) drawing on the GPU, as their renderer names it, with `vkcube`'s
frame rate within 1.5× of MoltenVK's natively on the same runner; and
runs the JDK workload through `runsc` on fwe, its benchmark beside
`runsc` on Linux.

## After 1.0

### M8 — Virtual networking

Multi-process and multi-container Linux applications on networks of their
own, as on a Linux host, with the host's TCP/IP stack carrying the
traffic at native speed.

- [ ] **Addresses per network namespace:** veth pairs and bridges as fwe's
  records, with the interfaces, addresses and routes netlink shows and
  sets; a socket bound or connected to a namespace's address is mapped to
  a host endpoint (a loopback port or a Unix socket) through a table all
  fwe processes share, with `connect`, `accept`, `getsockname` and
  `getpeername` translated, so no packet passes through fwe.
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
