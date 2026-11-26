# Roadmap

The status of each milestone, what is done, and the path to
[PLAN.md](PLAN.md)'s 1.0 as pull requests in order
([AGENTS.md](AGENTS.md#development-process)), with what is not planned. A
pull request is done when its **Done when** criteria pass as end-to-end
tests and benchmarks in CI; a milestone, when its pull requests are
merged. What runs unmodified is in [README.md](README.md#status); what
each Linux mechanism becomes under fwe, in
[docs/linux-on-macos.md](docs/linux-on-macos.md#what-fwe-enforces); the
current limitations, in
[docs/architecture.md](docs/architecture.md#known-limitations).

## Status

| Milestone | State |
|---|---|
| M0 Foundation | Done |
| M1 Core userland | Done |
| M2 Everyday software | Done but for the VM backend's run on real hardware |
| M3 Containers | Done |
| M4 Compatibility | Done |
| M5 Release | Done but for the first release (the owner's) |
| M6 Native speed and coverage | Under way: PRs 1 and 2 done |
| M7 Graphical programs and sandboxes | Under way: PRs 1, 2 and 3 done |
| M8 Virtual networking | After 1.0 |

## Done

- **M0 — Foundation:** CI, ELF loading, system calls trapped, an
  end-to-end harness.
- **M1 — Core userland:** processes, threads, memory, files in a Linux
  root filesystem, signals, pipes, glibc and musl dynamic linking.
- **M2 — Everyday software** (but the real-hardware run): networking,
  terminals and job control, `epoll` and the descriptor-based event calls,
  `/proc` and `/sys`, virtual credentials, the hypervisor backend.
- **M3 — Containers:** namespaces, cgroups v2, overlay mounts, seccomp,
  capabilities.
- **M4 — Compatibility:** the rest of Linux's call table that macOS can
  carry, ptrace for `strace` and `gdb`, Docker, rootless Podman, Wine's
  console programs in the VM. Every LTP system-call test that applies
  passes; the rest are listed with their reasons in
  `tools/ltp/exceptions.txt`.
- **M5 — Release** (but the release itself): benchmarks in CI, the
  system-call gate, the user guide with recipes CI runs, the Homebrew
  formula, `fwe --pull`, a signing and notarizing release workflow.
- **M6 PR 1 — Native speed:** benchmark budgets in CI; prepared images
  kept on disk by file identity; static executables linked below 4 GiB
  moved above it when their link kept relocations; code made at run time
  run by translation ([docs/jit.md](docs/jit.md)), its translations kept
  between runs; a JDK at work within budget; translated code within 1.3×
  of the same code natively.
- **M6 PR 2 — Kernel state in memory:** the process store, shared
  records, a file store for tmpfs, `/dev/shm`, memfds and the cgroup tree
  in memory every fwe process maps, or in macOS's own objects, none of it
  on disk; System V semaphores, messages and segments within 3× macOS.
- **M7 PR 1 — A display:** X11 clients on an X server on the Mac
  (XQuartz, Xvfb), `MIT-SHM` where the server takes segments by
  descriptor; Weston and Xwayland in the guest; demo programs
  (`xterm`, `xeyes`, `xclock`, GTK 3 and 4, Qt, Tk, `glxgears` by
  Mesa's software renderer, Wine's Notepad in the VM) driven and checked
  by screenshot; an X frame and request round trip benchmarked.
- **M7 PR 2 — The GPU:** fwe's own Linux Vulkan driver, each command
  passed to the Mac's Vulkan driver (MoltenVK, or KosmicKrisp) in fwe's
  process through one device ioctl; X11 swapchains on the driver's own;
  null descriptors where the Mac's driver lacks them; OpenGL through
  Zink; `vkcube` and `glxgears` drawn on it in CI; a Vulkan submission
  and `vkcube`'s frames within 1.5× of the same driver natively.
- **M7 PR 3 — Browsers and application frameworks:** Chromium and
  Firefox, sandboxes on, showing a page and playing a video; Electron,
  Visual Studio Code and Zed (by lavapipe) on Debian 13, the editors
  saving what is typed into them; Tauri and Wails apps of fwe's own built
  under fwe, drawing through WebKitGTK; Chromium's page load and video
  frames benchmarked against Chrome for Testing on macOS, Electron's
  start-up against its macOS build.

## Left to 1.0

### M2 and M5 — the owner's actions

- [ ] **The VM backend on real hardware:** the `hv_` tests pass in the
  self-hosted `hypervisor` CI job on a machine whose crash costs nothing
  ([docs/hypervisor.md](docs/hypervisor.md)); it needs a registered runner
  and the `FWE_HV_SELF_HOSTED` variable.
- [ ] **The first release:** the Developer ID secrets and a tagged
  release.

### M6 — Native speed and native coverage

Budgets, held in CI against native macOS on the same runner:

| Benchmark | Budget |
|---|---|
| a system call (`getpid`, `fstat`, `stat`, `open`+`close`, `pread`, `mmap`+`munmap`; one thread and several) | 1.5× |
| thread create and join; `fork` + exit + wait; `fork` + `exec` + wait; start-up | 3× |
| SQLite, git, a JDK at work, Node.js, LuaJIT, an X frame and round trip | 1.5× |
| a C build (Lua), a Lua script, a Python script, xz | fwe's share of CPU samples 1.2× |
| translated code (calls and returns, a switch, calls through a register, a loop) against the same code natively | 1.3× |
| a function made at run time and run (no native counterpart) | 2 µs |

#### PR 3 — Generated code run as it is, where it is sound

- [ ] **Clean pages run natively:** a page of generated code with no
  system call, thread-pointer access or `x18` use runs as it is,
  translated again once written; 4096 functions in turn within 1.3×.
- [ ] **A library called from generated code run natively,** its return
  into generated code taken as a fetch.

**Done when:** each is adopted with the JDK's, Node.js's and LuaJIT's
benchmarks holding, or listed as not planned with the counts.

#### PR 4 — File lookups without the host

- [ ] **Counted:** path lookups by kind and host calls per guest call.
- [ ] **Image layers cached** in memory every fwe process shares (an
  overlay's lower layers, which Linux too requires unchanged).
- [ ] **Directories cached,** checked before use against a kqueue watch.
- [ ] **`O_PATH` descriptors** open the host file only when a call needs
  it; per-descriptor bookkeeping made when asked for.
- [ ] **Benchmarks:** an absent name, a `stat` in an image layer,
  `open`+`close`; Python's start-up, `git status` in a large tree, a
  command started in a container.

**Done when:** a `stat` in an image layer and an absent name's lookup
hold 0.5× macOS (unless the directory cache is not planned), and
`open`+`close` 1.1×.

#### PR 5 — `fork` and signals

- [ ] **Fewer mappings to fork:** fwe's code cache, tables and descriptor
  room made on first use, in as few host regions as they can be.
- [ ] **`rt_sigreturn` through the gate,** without a host signal.

**Done when:** `fork` + exit + wait holds 2× macOS and a handled
`SIGSEGV` 2×.

#### PR 6 — 4 KiB pages natively

- [ ] `mmap`, `mprotect` and `munmap` at 4 KiB granularity on 16 KiB
  pages: contents at 4 KiB offsets copied in, each host page given its
  parts' union of protections and the stricter parts enforced by fwe, 4096
  in `AT_PAGESZ` for programs that need it. A layout that cannot be kept
  goes to the VM.

**Done when:** a program that needs 4 KiB pages runs natively in CI within
the system-call budget, and what still needs the VM is listed with the
reason.

#### PR 7 — Wine natively

- [ ] Code Wine maps executable prepared as a program's own (its `x18`
  uses rewritten, as Windows keeps the TEB there), its images' 4 KiB
  sections mapped as above; Windows console programs built for ARM64 run
  without `--vm`, benchmarked against the same sources built for macOS.

**Done when:** Wine's test program runs natively in CI and its benchmarks
hold 1.5×.

#### PR 8 — Large images natively

- [ ] **Counted:** per process, the code run by translation because no
  stub space reaches it, the code that translation follows into from
  there, and the time taken bringing in translations kept by earlier
  runs.
- [ ] **No band beyond reach:** every site of an image whose code is
  wider than a branch reaches across (Chromium's 224 MiB) gets a stub, or
  the code beyond reach and what it calls costs as native code does.
- [ ] **Kept translations brought in at the cost of a native page's first
  run,** not one lookup per block.

**Done when:** Chromium's page load holds 1.5× Chrome for Testing on
macOS, its budget back from 2.5×.

### M7 — Graphical programs and sandboxes

CI starts an X server and drives each program with synthetic input,
checking what it draws by screenshot.

#### PR 4 — Graphical Wine

- [ ] Wine's Notepad, Minesweeper and `regedit`, and a Direct3D demo,
  natively through Wine's X11 driver, Direct3D on the GPU through DXVK
  and VKD3D-Proton.

**Done when:** they draw in CI, the demo on the GPU.

#### PR 5 — gVisor on fwe

- [ ] `runsc` on its `systrap` or `ptrace` platform, started by Podman or
  Docker, running a JDK workload, benchmarked against `runsc` on Linux.

**Done when:** CI runs the JDK workload through `runsc` on fwe, its
benchmark beside `runsc` on Linux.

#### PR 6 — Applications on the GPU through MoltenVK

MoltenVK is the Vulkan driver every Apple Silicon Mac runs, so what
programs need on the GPU is made to work on it.

- [ ] **OpenGL 3 and OpenGL ES 3 on MoltenVK:** fwe's Vulkan driver
  gives what Zink and ANGLE need for them and MoltenVK lacks: transform
  feedback, and triangles whose flat values come from their last vertex.
- [ ] **Browsers on the GPU:** Firefox's WebGL 1 and 2 by Zink, and
  Chromium's GPU process by ANGLE on Vulkan, drawing pages on the Mac's
  GPU.
- [ ] **Zed on the GPU:** its shaders compile on MoltenVK, whose
  translation to Metal passes a structure's array member where a
  function takes `spvUnsafeArray` (Metal's compiler refuses it).

**Done when:** both browsers' WebGL names the Mac's GPU and draws the
test page in CI, antialiased, Chromium composites on the GPU, and Zed
edits a file on the GPU.

## After 1.0

### M8 — Virtual networking

Applications on networks of their own, as on a Linux host, the host's
TCP/IP stack carrying the traffic. Packet-level features (iptables,
packet sockets, TUN) would need a TCP/IP stack in fwe; they stay out
unless one proves cheap enough.

#### PR 1 — Addresses per network namespace

- [ ] veth pairs and bridges as fwe's records, with the interfaces,
  addresses and routes netlink shows; a socket on a namespace's address
  mapped to a host endpoint through a table all fwe processes share, so no
  packet passes through fwe.

**Done when:** two namespaces reach each other through veth pairs and a
bridge at loopback speed within 1.5×.

#### PR 2 — Container networks

- [ ] Podman's netavark and Docker's bridge driver set networks up through
  those calls; containers reach each other by name; published ports
  listen on the Mac; outgoing connections leave as the Mac's.

**Done when:** Docker Compose with a bridge network and a Podman pod run,
reaching each other by name, with a published port reachable from the Mac.

## Not planned for 1.0

Calls for these are refused (`ENOSYS`, `EINVAL` or `EPERM`) unless noted,
so programs that probe for them fall back.

- **io_uring.**
- **Networking beyond loopback and the host's sockets** (veth, bridges,
  firewalling, packet sockets, SCTP, RDS, TUN, kernel TLS): a new network
  namespace has loopback only; other families fail with `EAFNOSUPPORT`.
  Raw IP sockets need `CAP_NET_RAW` and fwe running as root. M8 adds
  namespace addresses and container networks.
- **Chosen pids in the initial pid namespace:** its pids are the host's;
  `set_tid` works in fwe's own pid namespaces.
- **`fanotify`:** its permission events would hold every process's file
  calls on another's answer.
- **`CLONE_FILES` without `CLONE_VM`:** two macOS processes cannot share a
  descriptor table; the child gets a copy.
- **Pipes over 64 KiB:** a host pipe holds no more.
- **Setting the clock, time namespaces:** fwe's root lacks
  `CAP_SYS_TIME`; `CLONE_NEWTIME` fails with `EINVAL`.
- **Disk filesystems and block devices:** files are the host's; fwe mounts
  tmpfs, proc, sysfs, cgroup2, devpts, mqueue and overlay.
- **Swap, huge pages, memory error injection** (but `MADV_HWPOISON`): the
  host manages memory.
- **cgroup resource limits but `pids.max`:** accepted, not enforced.
- **Per-process I/O counts** (`/proc/<pid>/io`): the host counts only
  storage bytes.
- **perf events, userfaultfd.**
- **Setting the initial UTS namespace's names:** they are the Mac's.
- **CPU affinity:** accepted, pins nothing.
- **x86 binaries,** Linux or Windows.
- **kselftests and gVisor's suite as gates:** LTP is the gate.
- **Translator techniques measured and not adopted:** lookups without a
  load (4096 functions 19.5–20.3 ns against the table's 19.7), inline
  caches (a call through a register 1.01 ns against 1.02), traces (0.6% of
  javac's block runs).
