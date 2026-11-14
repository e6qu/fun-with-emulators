# Roadmap

A milestone is done when its **Done when** criteria pass as end-to-end tests
in CI. [PLAN.md](PLAN.md) states the goal and the 1.0 finish line;
[docs/architecture.md](docs/architecture.md) lists the current limitations
in detail.

## Status

| Milestone | State |
|---|---|
| M0 Foundation | Done |
| M1 Core userland | Done |
| M2 Everyday software | Done but for the VM backend's run on real hardware |
| M3 Containers | Done |
| M4 Compatibility | Done: all 1213 of LTP's system-call tests that apply pass (1551 run) |
| M5 Release | Done but for the first release (the owner's) |
| M6 Native speed and coverage | Not started |
| M7 Virtual networking | Planned after 1.0 |

What runs unmodified, with its output checked in CI:
- **Natively, in-process:** Debian's coreutils, bash, git, SQLite, lighttpd,
  Node.js (V8's JIT), rustc with Cargo, and apt.
- **In the VM**, for executables linked below 4 GiB: Debian's Python, GCC,
  clang and Go, on the software stand-in for Hypervisor.framework only.
- **Containers:** crun, podman and containerd run the `alpine` image;
  podman builds images, pushes and pulls them through a registry and runs
  rootless, and Debian's podman runs in the VM; Docker loads, runs and
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
`/sys` programs read; virtual credentials; signals between processes and
threads; `vfork`, `posix_spawn`, `execveat`, `clone3`; `EFAULT` for bad
pointers; fwe's own descriptors out of the guest's reach; the hypervisor
backend for executables linked below 4 GiB, with threads, `fork`, `vfork`,
`execve` in both directions, pointer authentication and BTI. *The target
programs (git, compilers, Node, Go, Rust, apt, a database, a web server) run
unmodified.*

**M3 — Containers.** Mount, pid, user, UTS, IPC, network and cgroup
namespaces; cgroups v2 with device programs; overlay mounts; seccomp and
capabilities. *crun, podman and containerd run standard images.*

**M4 — Compatibility.** Every LTP system-call test that applies passes in
CI, the rest listed with their reasons in `tools/ltp/exceptions.txt`;
ptrace serves Alpine's `strace` and `gdb`; Docker Engine with BuildKit and
Compose, and podman building, pushing, pulling and running rootless (and
Debian's in the VM); Wine runs ARM64 Windows console programs under
`fwe --vm`; the rare `x18` forms are rewritten, and a binary without section
headers has its unwind table found through `PT_GNU_EH_FRAME`. *Each is
tested end to end in CI.* Beyond M3:
- **Processes and signals:** process descriptors (`pidfd_*`,
  `CLONE_PIDFD`, `waitid(P_PIDFD)`); real-time signals across processes;
  the parent-death signal; core dumps; resource limits; `CLONE_VM`
  processes; priorities, scheduling policies and CPU-time clocks; POSIX
  timers; ptrace of processes and threads (see below); robust futexes
  released as their owner ends, and `get_robust_list` of any thread;
  zombies in `/proc`; real-time signals queued; process accounting
  (`acct`); I/O priorities; `process_vm_readv` and `process_vm_writev`;
  Landlock.
- **Memory:** `mremap`, `madvise` and `msync` as Linux has them; the `mlock`
  family with accounting; `mincore`; `mseal`; `remap_file_pages`;
  `/proc/<pid>/maps`, `smaps` with `PROCMAP_QUERY`, `/proc/self/mem` and
  `pagemap`.
- **Files:** `preadv2`/`pwritev2`; `openat2`; `O_TMPFILE`; file handles;
  `ETXTBSY`; `fcntl` owners, signals, OFD locks, leases and pipe sizes;
  `splice`, `tee`, `vmsplice`; inotify and dnotify; native AIO;
  `sync`/`syncfs`; `file_getattr`/`file_setattr`; `cachestat`; owners and
  Linux's permission checks for a guest that is not root; loop devices.
- **Mounts and namespaces:** the new mount API (`fsopen` to `listmount`);
  propagation and mount flags acted on; `pivot_root` of a chroot; namespace
  descriptors with `setns` and the `NS_GET_*` requests.
- **IPC and sockets:** System V IPC and POSIX message queues per IPC
  namespace; keys and keyrings; socket arguments, options and requests as
  Linux checks them; `sendmmsg`/`recvmmsg`; eBPF maps and socket filters,
  their map accesses checked as they load; the IPC ids `kernel.*_next_id`
  chooses.
- **Waiting and time:** sleeps, timeouts, `poll`, `select` and timerfd as
  Linux reports them; `epoll_pwait2`; `futex_waitv`, requeue, bitsets and
  shared futexes.
- **Containers, further:** a thread's own root, working directory, mounts
  and namespaces (`unshare` and `setns` on one thread); namespace files
  bound to paths (`nsfs`); `CLONE_PARENT` children waited for by their
  parent; the host's loopback described over netlink.
- **Other calls:** `personality`, `getcpu`, `syslog`, `membarrier`,
  `readahead`, `sync_file_range`, `vhangup`, `reboot`, strict seccomp, the
  LSM calls, protection keys as on a CPU without them, and the clock
  refused as Linux refuses it without `CAP_SYS_TIME`.

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

- [x] **Performance:** benchmarks in CI of startup, system-call cost
  (one thread and several at once), `fork`/`exec` and a C project's
  build, against native macOS and Linux on arm64; system calls through a
  direct gate rather than a trap; a kernel lock whose reading calls run
  side by side.
- [ ] **Packaging:** a signed and notarized `fwe` with the hypervisor
  entitlement, a Homebrew formula, and a command that fetches and unpacks a
  Debian or Alpine root filesystem. In place: `fwe --pull` (CI pulls and
  runs Alpine's and Debian's images), the formula (`Formula/fwe.rb`, which
  CI installs and tests from source), and the release workflow, which
  signs under the hardened runtime and notarizes with a Developer ID.
  Left: the Developer ID secrets (an owner's action, not code) and the
  first release, whose tag the formula names.
- [x] **User documentation:** installing, running programs and containers,
  and what is not supported ([docs/user-guide.md](docs/user-guide.md),
  whose recipes CI runs as written).

**Done when:** a user installs a release and runs a Debian or Alpine
userland and podman with it, following the documentation.

### M6 — Native speed and native coverage

Linux code runs at native speed, and what fwe adds is held to budgets
([PLAN.md](PLAN.md#principles)); programs that now need the VM run
natively wherever fwe can make them fit the Mac.

- [ ] **Benchmark budgets in CI:** the benchmark job fails when fwe exceeds
  a budget against native macOS on the same runner (the C build, against
  native Linux running the same Alpine clang: macOS's is Apple's clang,
  another compiler). The budgets and the figures on the last run before
  this plan:

  | Benchmark | Budget | Last run |
  |---|---|---|
  | a system call (`getpid`, `getppid`, several threads at once) | 1.5× | 1.3×, 2.6×, 2.0× |
  | thread create and join | 3× | 15.8× |
  | `fork` + exit + wait | 3× | 4.7× |
  | `fork` + `exec` + wait | 3× | 11.6× |
  | start-up | 3× | 10× |
  | building a C project (Lua) | 1.5× | 3.9× |

  The work this calls for: start and end threads without per-thread files
  or scans; the per-process files written at start; `fork`'s cost per
  host region and per record; the memory calls on the kernel lock's
  shared side; and prepared images kept (below).
- [ ] **Prepared images kept:** the code fwe prepares in a program (its
  system calls, thread-pointer accesses and `x18` uses rewritten, and
  relocated where the next item needs it) is kept on disk by the file's
  identity and reused, as Rosetta 2 keeps its translations, so a program
  is prepared once rather than at every start, and a large one
  (libLLVM, a JIT runtime) starts as fast as a small one.
- [ ] **Executables linked below 4 GiB, natively:** static Go programs and
  Debian's non-PIE executables (`python3`, GCC, clang) moved above 4 GiB.
  arm64 code reaches its own code and data PC-relative (`adrp`, `adr`,
  branches), so moving the whole image by a multiple of the page keeps
  its code right; the absolute addresses are in its data (the GOT,
  init and fini arrays, pointer tables, Go's module data). They are found
  from relocations a binary keeps, and from the structures that hold them
  (the GOT and arrays the dynamic section names, Go's `moduledata` and
  `pclntab`), checked before the move; a binary whose pointers cannot all
  be accounted for runs in the VM as now, and why is recorded.
- [ ] **4 KiB pages natively:** `mmap`, `mprotect` and `munmap` at 4 KiB
  granularity on the Mac's 16 KiB pages: file contents at 4 KiB offsets
  copied in, each host page given the union of its parts' protections and
  the stricter parts enforced by fwe (a write to a read-only part caught
  and delivered as Linux would), and 4096 in `AT_PAGESZ` for a program
  that needs it. A layout that cannot be kept so (an execute-only part
  beside a writable one in one host page, say) sends the program to the
  VM.
- [ ] **Wine natively:** Windows' ARM64 code keeps the thread's TEB in
  `x18`, which macOS clears, so code Wine maps executable is prepared as
  a program's own is, with its `x18` uses rewritten; its images' 4 KiB
  sections are mapped as above. Wine then runs without `fwe --vm`.

**Done when:** the budgets hold in CI; static Go programs, Debian's
low-linked toolchain and Wine's test program run natively, in CI; and
what still needs the VM is listed with the reason.

## After 1.0

### M7 — Virtual networking

Multi-process and multi-container Linux applications on networks of their
own, as on a Linux host, with the host's TCP/IP stack carrying the
traffic, so that it moves at native speed.

- [ ] **Addresses per network namespace:** veth pairs and bridges as fwe's
  records, with the interfaces, addresses and routes netlink shows and
  sets; a socket bound or connected to a namespace's address is mapped to
  a host endpoint (a loopback port or a Unix socket) through a table all
  fwe processes share, with `connect`, `accept`, `getsockname` and
  `getpeername` translated, so no packet passes through fwe.
- [ ] **Container networks:** podman's netavark and Docker's bridge driver
  set them up through those calls; containers reach each other by address
  and by name (aardvark-dns, Docker's embedded resolver, which run as
  Linux programs); published ports listen on the Mac; outgoing
  connections leave as the Mac's, which is network address translation by
  construction.
- [ ] **A server process, only if needed:** for what must outlive every
  process of a network (a published port whose creator has ended), a
  per-user fwe process started on demand, as Wine's `wineserver` is.

Packet-level features (iptables and nftables rules, raw and packet
sockets, ICMP from containers, TUN) would need a TCP/IP stack inside fwe,
as gVisor has, which every packet would pass through; they stay out
unless one proves cheap enough for the principle above.

**Done when:** Docker Compose with a bridge network (a web application, a
database and a cache) and a podman pod run, their containers reaching
each other by name, with a published port reachable from the Mac.

## Not planned for 1.0

Calls for these are refused (`ENOSYS`, `EINVAL` or `EPERM`) unless noted, so
programs that probe for them fall back.
- **io_uring:** refused; programs fall back to ordinary system calls.
- **Networking beyond loopback and the host's sockets** (veth, bridges,
  firewalling, raw and packet sockets, SCTP, RDS, TUN, kernel TLS): a new
  network namespace has loopback only, and other protocols fail with
  `EAFNOSUPPORT` or `ENOPROTOOPT`. Addresses per namespace, bridges and
  container networks are planned after 1.0 (M7).
- **`kcmp`:** macOS cannot tell whether two descriptors share an open file
  description.
- **Chosen pids** (`clone3`'s `set_tid`, `/proc/sys/kernel/ns_last_pid`):
  pids are the host's, which macOS assigns.
- **`fanotify`:** its permission events would hold every process's file
  calls on another's answer; programs fall back to inotify.
- **A shared descriptor table without shared memory** (`CLONE_FILES`
  without `CLONE_VM`): two macOS processes cannot share one, so the child
  gets a copy.
- **Pipes over 64 KiB:** a host pipe holds no more, so a pipe starts at
  64 KiB, not Linux's 256 KiB with 16 KiB pages.
- **Setting the clock, and time namespaces:** fwe's root lacks
  `CAP_SYS_TIME`, as in a container, which setting the clock and a time
  namespace's offsets need; the Mac's clock is only read, and
  `CLONE_NEWTIME` fails with `EINVAL`.
- **Disk filesystems and block devices** (ext4, XFS, btrfs, quotas,
  fs-verity, RAM disks, SCSI): files are the host's, on its filesystem;
  fwe mounts tmpfs, proc, sysfs, cgroup2, devpts, mqueue and overlay, and
  its loop devices hold no filesystem.
- **Swap, huge pages and memory error injection:** the host manages
  memory; `swapon` fails with `ENOSYS`, as on a kernel without swap.
- **cgroup resource limits but `pids.max`** (memory, CPU, I/O): accepted,
  not enforced; the host shares its resources alike.
- **The page cache's figures** (`/proc/meminfo`'s `Cached`,
  `/proc/<pid>/io`): the host's cache does not report them per process.
- **perf events:** `perf_event_open` fails with `ENOSYS`.
- **userfaultfd:** a page fault handed to another thread to resolve would
  have fwe block the faulting thread in its signal handler, natively and
  in the VM; few programs use it (CRIU, QEMU's post-copy migration).
  `userfaultfd` fails with `ENOSYS`, and there is no `/dev/userfaultfd`.
- **Setting the initial UTS namespace's names:** they are the Mac's; a new
  UTS namespace's are the guest's to set.
- **CPU affinity:** macOS has none; `sched_setaffinity` is accepted and pins
  nothing.
- **x86_64 Linux binaries:** fwe runs arm64 code natively and emulates no
  other architecture.
- **Graphical programs**, Wine's included: out of the plan's scope.
- **x86 and x64 Windows programs under Wine:** they need an x86 emulator
  (FEX or box64).
- **kselftests and gVisor's system-call suite as gates:** LTP is the
  conformance gate.
