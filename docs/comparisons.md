# fwe and other ways to run Linux programs

Other ways to run a program built for one system on another: what each
does, how it differs from fwe, and what fwe takes from it. How fwe
itself works is in [architecture.md](architecture.md) and
[linux-on-macos.md](linux-on-macos.md).

## The design space

Running a Linux program elsewhere comes down to two questions.

**How does the program's code run?**

- **Natively:** the processor runs its instructions as they are. This
  needs the same instruction set (arm64 on arm64) and enough of the
  program's address-space assumptions to hold.
- **Translated:** its instructions are rewritten into the host's,
  ahead of time (a static translator) or as they run (a dynamic one).
- **Emulated:** an interpreter or a whole emulated machine runs it.
- **Rebuilt:** the source is compiled again for the host.

**Who answers its system calls?**

- **A real Linux kernel**, in a virtual machine.
- **A Linux personality in the host's kernel**: a second system-call
  table that translates to the host kernel's own services.
- **A Linux kernel written as an ordinary program** (a "userspace
  kernel"), which the program's calls are diverted to.
- **The host's kernel directly**, through a library that replaces the
  program's system interface (Wine's approach, for Windows).

fwe runs code natively and answers system calls with a userspace
kernel. Its native backend runs the program inside the `fwe` process and
diverts each `svc` to fwe's code. Its VM backend runs the program in a
Hypervisor.framework VM with no kernel in it, so each system call leaves
the VM for the same userspace kernel.

| | Code runs | System calls answered by | A Linux kernel? | One Linux process is one host process | Host files |
|---|---|---|---|---|---|
| **fwe** (native) | natively, in-process, a few instructions rewritten; JIT code from a code cache | fwe's userspace kernel, in the same process | no | yes | directly |
| **fwe** (VM) | natively, in a VM per process | fwe's userspace kernel, on VM exits | no | yes | directly |
| Wine | natively, in-process | Wine's DLLs and `wineserver` | — (Windows) | yes | directly |
| Lima, Colima, Docker Desktop, OrbStack | natively, in one Linux VM | Linux | yes | no | shared into the VM |
| Apple `container` | natively, in a VM per container | Linux | yes | no | shared into the VM |
| WSL1 | natively | a Linux personality in the NT kernel | no | yes (pico processes) | directly |
| WSL2 | natively, in one Linux VM | Linux | yes | no | shared into the VM |
| QEMU (system) | emulated, or natively with KVM/HVF | Linux, in the emulated machine | yes | no | shared into the VM |
| Noah | natively, in a VM per process | a userspace kernel, on VM exits | no | yes | directly |
| gVisor | natively | its userspace kernel (the Sentry) | no (on a Linux host) | one per address space; the Sentry's tasks are goroutines | through its Gofer, or the Sentry's own `*at` calls |
| Gramine | natively | a library OS in the process, under a patched C library | no | yes | the mounts its manifest names |
| User-Mode Linux | natively, under ptrace or seccomp | Linux itself, built to run as host processes | yes | per address space | its own file systems, `hostfs` |
| illumos lx zones | natively | a Linux brand in the illumos kernel, with a user-space library for the rest | no | yes | the zone's own |
| QEMU user mode | translated as it runs | the host Linux kernel, through a thin layer | host's | yes | directly |
| DynamoRIO | copied into a code cache as it runs | the host kernel | host's | yes | directly |
| FEX, Box64 | translated as it runs | the host Linux kernel | host's | yes | directly |
| FreeBSD Linuxulator, NetBSD `compat_linux` | natively | a Linux personality in the BSD kernel | no | yes | directly, `/compat/linux` (`/emul/linux`) first |
| Darling (the reverse: macOS programs on Linux) | natively | a macOS C library over Linux's calls, and a server for Mach's | — (macOS) | yes | in a Linux container of its own |
| Homebrew, Nix | rebuilt for macOS | macOS | — | yes | directly |
| Rosetta 2 | translated ahead of time, and as it runs | macOS (it changes the CPU, not the OS) | — | yes | directly |

## Running Windows programs: Wine

Wine runs Windows programs on Linux and macOS. It loads a Windows
program (a PE file) into an ordinary Unix process and runs its code
natively when the processor matches. Windows' stable interface is not
its system calls, whose numbers change between Windows releases, but the
functions its system DLLs export (`ntdll`, `kernel32`, `user32` and the
rest), so Wine reimplements those DLLs. A program's call into Windows is
then an ordinary function call into Wine's code, which calls the host.
What processes share (handles, synchronisation objects, the registry) is
kept by `wineserver`, a separate process every Wine process talks to.

**How fwe differs.** Linux's stable interface is the system-call
instruction itself: static binaries, Go programs and musl make system
calls directly, with no library in between. fwe therefore intercepts at
the instruction (`svc`) and implements the kernel, not a library. What
processes share (process records, the futex table, namespaces) lives in
memory every fwe process maps, so there is no server process.

**In common.** Both run code natively in-process, make one host process
per guest process, and contend with macOS for low addresses. Wine
reserves them with a preloader before macOS takes them; fwe moves a
static program linked below 4 GiB whose link kept its relocations, and
runs any other in its VM backend. fwe also runs Linux's Wine itself, in
the VM backend (CI's `wine` job), so Windows programs run on fwe through
Wine as on Linux.

## Linux in a virtual machine

### Lima and Colima

Lima runs a Linux VM on macOS (on QEMU or Apple's
Virtualization.framework), with a guest agent that forwards ports and
shares host directories into the VM (virtiofs, 9p or sshfs). Colima
builds on Lima to offer Docker, containerd or Kubernetes, the runtime
running in the VM and its socket forwarded to macOS. Docker Desktop,
Podman Machine and OrbStack follow the same pattern with their own VMs.

**How fwe differs.** A Linux program under fwe is a macOS process: it
shows in Activity Monitor, uses the Mac's files in place rather than
through a shared filesystem, uses the Mac's network stack and ports, and
takes memory as it needs it rather than from a VM's fixed allotment.
There is no VM to boot, so a program starts in milliseconds. The price is
compatibility: a VM runs the real Linux kernel, whose behaviour is right
by definition; fwe is as faithful as its implementation, measured by LTP
([ROADMAP.md](../ROADMAP.md#status)).

### WSL1 and WSL2

WSL1 runs Linux programs on Windows as "pico processes" whose system
calls the NT kernel passes to a Linux personality in the kernel: fwe's
design, inside the host's kernel rather than beside it. Microsoft
followed it with WSL2, a real Linux kernel in a lightweight VM, chiefly
because of file-system performance (Linux programs' many small file
operations on NTFS through the personality) and the long tail of kernel
behaviour that is hard to match.

**For fwe.** WSL1's mechanism is fwe's model, and its weakness is the
risk this design carries: fidelity in the long tail. fwe measures it
with LTP and with real programs in CI ([README.md](../README.md#status)).
Its file operations are the host's own calls on APFS, with no
translation layer of the kind WSL1 had over NTFS, though fwe still
resolves each path (mounts, overlays, the root).

### QEMU and KVM

QEMU emulates a whole machine; with a hypervisor accelerator (KVM on
Linux, Hypervisor.framework on macOS) it runs the guest's code natively
and emulates only the devices. It runs a complete Linux kernel and
userland. KVM is Linux's interface for running VMs: a process creates a
VM and its virtual CPUs and runs them until they exit to it.

**For fwe.** fwe's VM backend uses Hypervisor.framework as a KVM user
would, but runs no kernel in the VM: the guest runs at EL0, and its
system calls and faults exit to fwe, which answers them with the same
code the native backend uses (see
[linux-on-macos.md](linux-on-macos.md#how-the-vm-is-actually-used)).

### Apple's `container`

Apple's `container` tool (on its Containerization framework) runs each
Linux container in a lightweight VM of its own, through
Virtualization.framework, with a small Linux kernel and init, giving
each container its own kernel and network address.

**How fwe differs.** fwe runs the container runtimes themselves (Podman,
crun, containerd, Docker) as Linux programs, and their containers as
macOS processes in fwe's namespaces, with no VM per container. Isolation
is weaker: see
[Isolation and security](linux-on-macos.md#isolation-and-security).

## A userspace Linux kernel

### Noah

Noah (2016–2017) ran Linux x86-64 programs on Intel Macs by putting each
process in a Hypervisor.framework VM with no kernel and handling its
system calls, which exit the VM, in a macOS process. It is the direct
predecessor of fwe's VM backend.

**How fwe differs.** fwe runs most programs natively in-process, without
a VM, and keeps the VM for those that need it; it runs on Apple Silicon;
and its kernel goes much further (namespaces, cgroups, ptrace, seccomp,
containers).

### gVisor

gVisor is a Linux kernel written in Go, the Sentry, that runs Linux
programs on Linux hosts as a security sandbox: their system calls go to
the Sentry instead of the host kernel, which they reach only through a
small set of the Sentry's own calls, and files through a separate
process (the Gofer), or with the Sentry's own descriptor-relative calls
on the mounts the Gofer hands it (directfs). Its "platforms" divert the
calls: KVM (the program runs in a VM, as in fwe's VM backend, the Sentry
acting as its guest kernel and its VMM), and `systrap`, the default,
which uses seccomp to turn each call into a `SIGSYS` its stub hands to
the Sentry and, on x86-64 only, patches the `syscall` sequence into a
jump to a trampoline, as fwe's native backend rewrites `svc` into a
branch to its gate. On arm64 every call takes the signal. The older
`ptrace` platform is no longer supported.

**How fwe differs.** gVisor's purpose is isolation on a Linux host, so it
keeps the program away from the host kernel and its memory. fwe's
purpose is compatibility on a macOS host: in the native backend the
program shares fwe's address space, so fwe is no sandbox against a
hostile program (see
[Isolation and security](linux-on-macos.md#isolation-and-security)).
The two compose: `runsc` is a Linux program, and running it on fwe, its
`systrap` platform included, is a 1.0 goal (M7).

### User-Mode Linux and LKL

User-Mode Linux is Linux itself ported to run as host processes (the
`um` architecture): the guest's programs run in host processes it traces
with ptrace's `PTRACE_SYSEMU`, or since 2025 under a seccomp filter of a
stub's, and every system call is Linux's own code. It boots a
distribution, whose init is its process 1. LKL builds Linux as a library
an application links and calls, with no guest processes at all.

**How fwe differs.** Both get Linux's behaviour exactly by running
Linux's code, at the price of running a second kernel with its own
memory management and scheduler over the host's. fwe's processes,
threads, memory and files are the host's own, with Linux's semantics
added where they differ.

### Gramine

Gramine (formerly Graphene) is a library OS: a Linux kernel interface
inside each process, reached through a patched glibc or musl (or seccomp
trapping a raw `syscall`), over a narrow host interface; its main use is
running Linux programs in Intel SGX enclaves. Each guest process is a
host process; `fork` sends a checkpoint of the process to a new one, the
first process hands out the virtual pids, and the files a program sees
are the mounts its manifest declares. Shared futexes, System V shared
memory and `unshare` are not implemented.

**How fwe differs.** fwe needs no patched C library: it catches the
`svc` instruction itself, so static programs, Go's and any raw system
call work. Its kernel state shared between processes (futexes, System V
IPC, namespaces) is in memory they all map, not handed around by
messages.

### Darling: the reverse direction

Darling runs macOS programs on Linux. Its own `libsystem_kernel` turns
BSD calls into Linux's, and Mach traps become messages to
`darlingserver`, a user-space server built from XNU's source (it
replaced a Linux kernel module in 2022). A macOS program's raw system
call, made without the library, fails. Its programs run in a Linux
container whose process 1 is macOS's `launchd`.

**How fwe differs.** macOS's stable interface is its C library, as
Windows' is its DLLs, so Darling intercepts there, as Wine does; Linux's
is the instruction, so fwe intercepts there.

## Translating or instrumenting code

### QEMU user mode

`qemu-aarch64` and its kin run a Linux program built for one processor
on a Linux host of another, translating its code as it runs (QEMU's TCG)
and passing its system calls to the host Linux kernel, converting
structures where the two architectures lay them out differently. It
needs a Linux host: the kernel interface stays Linux's.

**For fwe.** The host's kernel is macOS's, so passing calls through is
not possible; the processor is the same, so translation is not needed.
fwe does the opposite half of QEMU user mode's job.

### DynamoRIO

DynamoRIO runs a program's code from a code cache: each block is copied
into the cache, instrumented, and run there, so every instruction the
program executes is seen, including code made at run time. Pin and
Valgrind work alike.

**For fwe.** Running everything from a cache would find every system
call with certainty, at the cost of a large engine and typically tens of
percent of speed. fwe does it only for code a program makes at run time
(a JIT compiler's): when the program jumps there, the block is translated
into fwe's code cache and run from there, and the program's memory stays
as it wrote it. Code loaded from files it rewrites in place instead,
guided by the program's unwind tables and symbols, and traps where it
cannot rewrite (see
[linux-on-macos.md](linux-on-macos.md#which-instructions-get-translated-and-how)).
How its translation, and DynamoRIO's, QEMU's, FEX's and Box64's, learn
that code changed and share their code caches is in
[jit.md](jit.md#how-others-do-it).

### FEX and Box64

FEX-Emu and Box64 run x86 Linux programs on arm64 Linux by translating
their code as it runs. Both also "thunk" common libraries: a program's
call into, say, its OpenGL or SDL library goes to the host's native
arm64 library instead of a translated x86 copy.

**For fwe.** Their translation does not apply to arm64 programs on an
arm64 host. Their thunking does, for the GPU: fwe's Linux Vulkan driver
packs each Vulkan command a program makes into one `ioctl` on fwe's GPU
device, and fwe calls the Mac's Vulkan driver (MoltenVK or KosmicKrisp)
for it in the same process, so the program draws on Metal without a
translated or emulated GPU. FEX or Box64 would be what runs x86 Windows
programs under Wine, which is not planned for 1.0.

### Rosetta 2

Rosetta 2 runs x86-64 macOS programs on Apple Silicon. It translates a
program ahead of time, when installed or first run, keeps the result in
a cache, and translates code made at run time as it appears. The
operating-system interface does not change: an x86-64 macOS program's
calls are macOS's. Apple also offers Rosetta inside Linux VMs, to run
x86-64 Linux programs there.

**For fwe.** fwe prepares a program's code (finds and rewrites its
system calls, thread-pointer accesses and `x18` uses) and keeps what it
found on disk by the file's identity, as Rosetta keeps its translations,
so a later start replays it rather than scanning again
([architecture.md](architecture.md)). Rosetta-style translation is
allowed where it is feasible and sound ([PLAN.md](../PLAN.md#principles)).

## A Linux personality in another kernel: FreeBSD's Linuxulator

FreeBSD runs Linux programs with the Linuxulator (`linux.ko`,
`linux64.ko`, on arm64 too). The kernel recognises a Linux
ELF at `execve` and gives the process a second system-call table; Linux
code runs natively, and its system calls go to `linux_*` functions in the
kernel that translate arguments, structures, errno values and signals to
FreeBSD's implementation. A Linux userland is installed under
`/compat/linux`, which path lookups try first, so a Linux program finds
its `ld.so` and libraries there; `linprocfs` and `linsysfs` provide
`/proc` and `/sys`. Linux threads are FreeBSD threads, and services
are FreeBSD's: its init and `rc` stay process 1. Namespaces are not
emulated (`unshare` and `setns` are stubs); jails isolate instead.

NetBSD's `compat_linux` works the same way, on aarch64 too, its Linux
tree under `/emul/linux`. OpenBSD removed its i386-only version in
OpenBSD 6.0 (2016), unmaintained and little used.

**How fwe differs.** fwe is this design moved out of the kernel, because
macOS does not let a program add a system-call table (kernel extensions
are deprecated, and none could). What a kernel personality gets for free,
fwe builds:

| | Linuxulator | fwe |
|---|---|---|
| reaching the Linux handler | a second table, chosen at `execve` | `svc` rewritten into a branch to fwe's gate; a trap where it cannot be |
| signals | the kernel builds Linux's frame | fwe's handlers record them and build Linux's frame |
| `fork`, threads | the kernel's own | the host's, with fwe's state copied or shared across |
| memory | the kernel's own | the host's `mmap`, with fwe's bookkeeping |
| a userland | `/compat/linux`, tried before `/` | `--root`, the whole view (`fwe --pull` makes one) |
| `/proc`, `/sys` | `linprocfs`, `linsysfs` | fwe's synthetic files |
| containers | Linux's namespaces largely absent | namespaces, cgroups and mounts of fwe's own |

### illumos lx branded zones

illumos runs a Linux distribution in a zone with the lx brand: a Linux
call traps into the illumos kernel, whose brand module serves what it
can and sends the rest back out to a user-space library in the process,
on a stack of its own. The brand has its own `/proc`, `/sys` and
cgroups, and the zone is the container (Joyent's Docker service ran
images as lx zones). Its `lxinit` sets up the zone and then runs the
distribution's own `/sbin/init`, systemd included, telling it that it is
in a container. Sun added lx in 2006 and removed it in 2010; Joyent
revived it in 2014, and it is maintained; it runs x86 programs.

**For fwe.** lx is the nearest design to fwe's: a Linux personality with
containers built in, part of it in user space. fwe puts all of it in user
space, and runs no Linux init (see [init and services](#init-and-services)).

## Rebuilding for macOS: Homebrew and Nix

Homebrew and Nix build programs for macOS from source (or install builds
made so), so they run as macOS programs with no translation at all: the
fastest way to run what has been ported. What has not been ported
(anything that needs namespaces, cgroups, `/proc`, Linux's system calls:
container runtimes, much server software, Linux-only tools) cannot be
had this way, and neither can a given binary, such as a vendor's build
or a container image. Nix builds
Linux packages on a Mac with a Linux VM (its `linux-builder`).

**For fwe.** fwe is for the other case: running the Linux build itself.
Homebrew's builds are also what fwe's benchmarks compare against, and how
fwe is installed (`Formula/fwe.rb`).

## A Linux kernel outside Linux, part by part

How the systems that answer Linux's system calls without Linux's kernel
do each part of a kernel's job: fwe; gVisor; WSL1; the BSDs' Linux
personalities (FreeBSD's Linuxulator, NetBSD's `compat_linux`); illumos's
lx zones; Noah; Gramine. Wine and Darling appear where they show another
way. fwe's side is detailed in [linux-on-macos.md](linux-on-macos.md) and
[architecture.md](architecture.md).

### Where the kernel is, and how a call reaches it

| | Where the Linux kernel's code is | How a system call reaches it |
|---|---|---|
| fwe | a library in each guest's own host process; what processes share, in memory they all map | `svc` rewritten into a branch to fwe's gate, or a trap where it cannot be rewritten; in the VM, a VM exit |
| gVisor | the Sentry, a separate Go process | systrap: seccomp's `SIGSYS`, the site patched into a jump on x86-64; KVM: a VM exit |
| WSL1 | `lxcore.sys`, in the NT kernel | NT passes a pico process's calls to it |
| Linuxulator, NetBSD | the BSD kernel | the trap, through a second system-call table chosen at `execve` |
| illumos lx | the illumos kernel, and a library in the process | the trap; what the kernel does not serve goes back out to the library |
| Noah | a macOS process per guest process | a VM exit (`syscall` left disabled, so it faults) |
| Gramine | a library OS in the process | a call from a patched C library, or seccomp trapping a raw `syscall` |
| Wine, Darling | libraries in the process, and a server process | a function call into the replaced system library |

### Processes, threads and fork

| | A process, a thread | `fork` | Pids |
|---|---|---|---|
| fwe | a host process, a host thread | the host's `fork`, fwe's state copied; in the VM a new fwe process sent the parent's memory | the host's; numbered from 1 in a pid namespace of fwe's |
| gVisor | a goroutine of the Sentry per task, a stub process per address space | the Sentry copies the address space, copy-on-write | the Sentry's |
| WSL1 | an NT process and thread | NT's own, extended for WSL | lxcore's |
| Linuxulator, NetBSD | a BSD process and thread (an LWP) | the BSD kernel's | the BSD kernel's |
| illumos lx | an illumos process and LWP | the kernel's | the kernel's |
| Noah | a macOS process, a vCPU on a host thread | the VM torn down, the host's `fork`, the VM rebuilt in both (not with threads) | the host's |
| Gramine | a host process (an enclave under SGX) | a checkpoint sent to a new process | virtual, handed out by the first process |

### Signals and memory

| | Signals | Memory |
|---|---|---|
| fwe | fwe's handlers record them and build Linux's frame; signals macOS lacks go through mailboxes of fwe's | the host's `mmap` at the guest's addresses (16 KiB pages); in the VM, stage-1 page tables of fwe's (4 KiB) |
| gVisor | the Sentry's own queues and frames | the Sentry's own VMAs over a memory file mapped into the stubs |
| WSL1 | lxcore | NT's memory manager, given 4 KiB granularity for pico processes |
| Linuxulator, NetBSD | numbers translated, Linux's frame built by the kernel | the BSD kernel's, flags translated |
| illumos lx | every signal first to the library, on its own stack | the kernel's |
| Noah | host handlers set a bit; the frame is built before the next VM entry | identity-mapped guest tables, `hv_vm_map` per call |
| Gramine | the library OS builds the frame; host signals ignored but `SIGTERM` | host mappings; `mprotect` ignored under SGX without EDMM |

### Files, `/proc` and `/sys`

| | The guest's files | `/proc`, `/sys` |
|---|---|---|
| fwe | the host's files, the root (`--root`) the whole view, through fwe's mount tables per namespace; owners and modes the host cannot hold kept in extended attributes; tmpfs, `/dev/shm` and memfds in a store of fwe's in shared memory | fwe's own |
| gVisor | its own VFS: host files through the Gofer or directfs, a writable overlay over the root | the Sentry's own |
| WSL1 | its own VFS: VolFs keeps Linux's metadata in NTFS extended attributes; DrvFs for Windows' drives | lxcore's own |
| Linuxulator, NetBSD | the host's VFS, `/compat/linux` (`/emul/linux`) tried first | `linprocfs` and `linsysfs`; NetBSD's procfs in Linux's form |
| illumos lx | the zone's own root | the brand's own |
| Noah | its own resolver: `/Users`, `/dev` and `/tmp` the host's, the rest under `~/.noah/tree` | none |
| Gramine | the mounts the manifest declares, fixed; `chown` does nothing | a few files |

### Sharing between processes, namespaces and cgroups

| | Futexes, System V IPC | Namespaces, cgroups, containers |
|---|---|---|
| fwe | shared futexes and semaphores on macOS's `__ulock` calls, System V and POSIX objects in shared records | every namespace but time's; cgroup v2's tree, freezing, killing, delegation and `pids.max` enforced, other controllers' limits kept but not enforced; Podman, Docker, containerd and runc run |
| gVisor | its own | most namespaces, cgroupfs and cgroup2fs; it is itself a container runtime (`runsc`), and Docker runs inside it |
| WSL1 | lxcore's own, built release by release | mount namespaces only |
| Linuxulator, NetBSD | translated to the BSD kernel's | none (stubs); jails instead |
| illumos lx | the kernel's, with epoll and inotify added | the zone is the container; cgroups emulated |
| Noah | macOS's System V objects; futexes within a process only | none |
| Gramine | private futexes only; no System V shared memory | none |

### Init and services

| | Process 1 | An orphan goes to | Services |
|---|---|---|---|
| fwe | the host's `launchd`, or a pid namespace's first process | Linux's adopter (subreaper or namespace init), else `launchd` | `launchd` jobs running `fwe`; no Linux init ([linux-on-macos.md](linux-on-macos.md#init-orphans-and-daemons)) |
| gVisor | the container's entrypoint | Linux's adopter, by the Sentry's rules | the container's |
| WSL1 | Microsoft's own `/init` | `/init` | none: no systemd (WSL2, a real Linux kernel, added it in 2022) |
| Linuxulator, NetBSD | the BSD's `init` | the BSD's `init` | the BSD's `rc` |
| illumos lx | the distribution's own `/sbin/init`, systemd included | that init | the distribution's |
| Noah | none | the host's `launchd` | none |
| Gramine | the entrypoint | the host, which reaps them | none |
| Darling | macOS's `launchd`, in a Linux pid namespace | `launchd` | macOS's daemons, started by `launchd` |

### Isolation, language and state

| | Isolation | Language, size | State |
|---|---|---|---|
| fwe | none by design: the native backend shares fwe's address space ([Isolation and security](linux-on-macos.md#isolation-and-security)) | Rust, about 4.9 MB of kernel crate source | active |
| gVisor | a sandbox: the Sentry itself under seccomp, no call passed through | Go, about 7.3 MB in `pkg/sentry` | active |
| WSL1 | the NT kernel's; lxcore in ring 0 | C, closed (left out when WSL was opened in 2025) | superseded by WSL2 |
| Linuxulator, NetBSD | the BSD kernel's; jails | C, about 1.8 MB (FreeBSD) | active; FreeBSD's arm64 since 12.0, NetBSD's since 10 |
| illumos lx | zones | C | active, x86 |
| Noah | none | C, about 0.5 MB | archived in 2020 |
| Gramine | against a hostile host, under SGX | C, about 3.2 MB | active |

In-kernel personalities have tended to end or close: OpenBSD dropped its
own in 2016, Sun dropped lx in 2010, and WSL1's lxcore stayed closed
when WSL was opened. The user-space designs (gVisor, Wine, Gramine,
User-Mode Linux, Darling, which moved its kernel module to a user-space
server) are all maintained.

### Sources

Each as read on 2026-11-25 (sizes are bytes of source, counted then).

- gVisor: [platforms](https://gvisor.dev/docs/architecture_guide/platforms/),
  [systrap](https://gvisor.dev/blog/2023/04/28/systrap-release/),
  [directfs](https://gvisor.dev/blog/2023/06/27/directfs/),
  [security](https://gvisor.dev/docs/architecture_guide/security/),
  [system calls](https://gvisor.dev/docs/user_guide/compatibility/linux/amd64/),
  [`task_exit.go`](https://github.com/google/gvisor/blob/master/pkg/sentry/kernel/task_exit.go).
- WSL1: [pico processes](https://learn.microsoft.com/en-us/archive/blogs/wsl/pico-process-overview),
  [system calls](https://learn.microsoft.com/en-us/archive/blogs/wsl/wsl-system-calls),
  [file systems](https://learn.microsoft.com/en-us/archive/blogs/wsl/wsl-file-system-support),
  [release notes](https://learn.microsoft.com/en-us/windows/wsl/release-notes),
  [systemd in WSL2](https://devblogs.microsoft.com/commandline/systemd-support-is-now-available-in-wsl/),
  [WSL opened](https://blogs.windows.com/windowsdeveloper/2025/05/19/the-windows-subsystem-for-linux-is-now-open-source/).
- FreeBSD: [linux(4)](https://man.freebsd.org/cgi/man.cgi?query=linux&sektion=4),
  [Linux emulation](https://docs.freebsd.org/en/articles/linux-emulation/),
  [`linux_dummy.c`](https://cgit.freebsd.org/src/plain/sys/compat/linux/linux_dummy.c),
  [1:1 threads](https://reviews.freebsd.org/rS283383).
  NetBSD: [compat_linux(8)](https://man.netbsd.org/compat_linux.8).
  OpenBSD: [6.0](https://www.openbsd.org/60.html).
- illumos lx: [lx(7)](https://smartos.org/man/7/lx),
  [`lx_brand.c`](https://github.com/TritonDataCenter/illumos-joyent/blob/master/usr/src/uts/common/brand/lx/os/lx_brand.c),
  [`lxinit.c`](https://github.com/TritonDataCenter/illumos-joyent/blob/master/usr/src/lib/brand/lx/lx_init/lxinit.c).
- Noah: [source](https://github.com/linux-noah/noah).
  Gramine: [features](https://gramine.readthedocs.io/en/stable/devel/features.html),
  [Graphene (EuroSys 2014)](https://www.cs.unc.edu/~porter/pubs/tsai14graphene.pdf).
- User-Mode Linux: [the kernel's guide](https://docs.kernel.org/virt/uml/user_mode_linux_howto_v2.html).
  LKL: [source](https://github.com/lkl/linux).
- Wine: [`signal_arm64.c`](https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/unix/signal_arm64.c),
  [wineserver(1)](https://man.archlinux.org/man/wineserver.1.en).
  Darling: [system calls](https://docs.darlinghq.org/internals/basics/system-call-emulation.html),
  [darlingserver](https://docs.darlinghq.org/internals/darlingserver/index.html),
  [containers](https://docs.darlinghq.org/internals/basics/containerization.html).

## What fwe takes from each

- From **Wine** and **WSL1**: native execution in-process, one host
  process per guest process, state shared between processes outside any
  one of them.
- From **FreeBSD's Linuxulator**: a Linux personality over the host's own
  services, and a separate Linux userland as the program's view.
- From **illumos's lx zones**: containers as part of the personality,
  with their own `/proc`, `/sys` and cgroups.
- From **gVisor**: a Linux kernel as an ordinary program, and diverting
  system calls by patching the instruction into a jump.
- From **Noah** and **KVM** users: a VM with no kernel for what cannot run
  in-process.
- From **DynamoRIO**: a code cache for code made at run time.
- From **FEX** and **Box64**: a guest library thunked to the host's, for
  Vulkan.
- From **Rosetta 2**: prepared code kept between runs.
- From **WSL1**'s successor: the warning to measure fidelity, not assume
  it.
