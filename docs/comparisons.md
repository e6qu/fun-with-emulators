# fwe and other ways to run Linux programs

There are many ways to run a program built for one system on another.
This document places fwe among them: what each does, how it differs
from fwe, and what fwe takes from it. How fwe itself works is in
[architecture.md](architecture.md) and [linux-on-macos.md](linux-on-macos.md).

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
kernel. Its native backend runs the program inside the `fwe` process,
diverting each `svc` to fwe's code; its VM backend runs the program in
a Hypervisor.framework VM that has no kernel in it, so that each system
call leaves the VM for the same userspace kernel.

| | Code runs | System calls answered by | A Linux kernel? | One Linux process is one host process | Host files |
|---|---|---|---|---|---|
| **fwe** (native) | natively, in-process, a few instructions rewritten | fwe's userspace kernel, in the same process | no | yes | directly |
| **fwe** (VM) | natively, in a VM per process | fwe's userspace kernel, on VM exits | no | yes | directly |
| Wine | natively, in-process | Wine's DLLs and `wineserver` | — (Windows) | yes | directly |
| Lima, Colima, Docker Desktop, OrbStack | natively, in one Linux VM | Linux | yes | no | shared into the VM |
| Apple `container` | natively, in a VM per container | Linux | yes | no | shared into the VM |
| WSL1 | natively | a Linux personality in the NT kernel | no | yes (pico processes) | directly |
| WSL2 | natively, in one Linux VM | Linux | yes | no | shared into the VM |
| QEMU (system) | emulated, or natively with KVM/HVF | Linux, in the emulated machine | yes | no | shared into the VM |
| Noah | natively, in a VM per process | a userspace kernel, on VM exits | no | yes | directly |
| gVisor | natively | its userspace kernel (the Sentry) | no (on a Linux host) | yes | through its Gofer |
| QEMU user mode | translated as it runs | the host Linux kernel, through a thin layer | host's | yes | directly |
| DynamoRIO | copied into a code cache as it runs | the host kernel | host's | yes | directly |
| FEX, Box64 | translated as it runs | the host Linux kernel | host's | yes | directly |
| FreeBSD Linuxulator | natively | a Linux personality in FreeBSD's kernel | no | yes | directly, `/compat/linux` first |
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
the instruction (`svc`) and implements the kernel, not a library. fwe
keeps what processes share in shared files and memory every fwe process
maps (process records, the futex table, namespaces), so it needs no
server process.

**In common.** Both run code natively in-process, both make one host
process per guest process, and both fight macOS for low addresses: Wine
reserves them with a preloader before macOS takes them; fwe runs a
program linked below 4 GiB in its VM backend. fwe runs Alpine's Wine
itself, in the VM backend (CI's `wine` job).

## Linux in a virtual machine

### Lima and Colima

Lima runs a Linux VM on macOS (on QEMU or Apple's
Virtualization.framework), with a guest agent that forwards ports and
shares host directories into the VM (virtiofs, 9p or sshfs). Colima
builds on Lima to offer Docker, containerd or Kubernetes, the runtime
running in the VM and its socket forwarded to macOS. Docker Desktop,
Podman Machine and OrbStack follow the same pattern with their own VMs.

**How fwe differs.** A Linux program under fwe is a macOS process: it
shows in Activity Monitor, uses the Mac's files where they are rather
than through a shared filesystem, uses the Mac's network stack and
ports, and takes memory as it needs it rather than from a VM's fixed
allotment. There is no VM to boot, so a program starts in milliseconds.
The price is compatibility: a VM runs the real Linux kernel, whose every
behaviour is right by definition; fwe is as faithful as its
implementation (all 1213 of LTP's system-call tests that apply pass).

### WSL1 and WSL2

WSL1 ran Linux programs on Windows as "pico processes" whose system calls
the NT kernel sent to a Linux personality in the kernel. It was the
closest predecessor to fwe's design, inside the host's kernel rather
than beside it. Microsoft replaced it with WSL2, a real Linux kernel in
a lightweight VM, chiefly because of file-system performance (Linux
programs' many small file operations on NTFS through the personality)
and the long tail of kernel behaviour that is hard to match.

**For fwe.** WSL1's history is the risk this design carries: fidelity
in the long tail. fwe measures it with LTP and with real programs in
CI (Debian's bash, git, apt, Node.js and rustc; podman, containerd,
Docker; Wine). Its file operations are the host's own calls on APFS,
without a translation layer of the kind WSL1 had over NTFS, but each
path is still resolved by fwe (mounts, overlays, the root).

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

**How fwe differs.** fwe runs container runtimes themselves (podman,
crun, containerd, Docker) as Linux programs, and their containers as
macOS processes in fwe's namespaces, with no VM per container. Isolation
is accordingly weaker: see
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
process (the Gofer). Its "platforms" divert the calls: `ptrace`, KVM (the
program runs in a VM, as in fwe's VM backend), and `systrap`, which uses
seccomp to catch the first call at each site and then patches the
`syscall` instruction into a jump to a stub, as fwe's native backend
rewrites `svc` into a branch to its gate.

**How fwe differs.** gVisor's purpose is isolation on a Linux host, so it
keeps the program away from the host kernel and its memory. fwe's
purpose is compatibility on a macOS host: in the native backend the
program shares fwe's address space, so fwe is no sandbox against a
hostile program (see
[Isolation and security](linux-on-macos.md#isolation-and-security)).

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

**For fwe.** This would find every system call with certainty, in code
fwe's scanner cannot tell from data and in JIT code, at the cost of
running everything from a cache (typically tens of percent slower, and a
large engine). fwe rewrites code in place instead, guided by the
program's unwind tables and symbols, and falls back to traps where
rewriting is not possible (see
[linux-on-macos.md](linux-on-macos.md#which-instructions-get-translated-and-how)).

### FEX and Box64

FEX-Emu and Box64 run x86 Linux programs on arm64 Linux by translating
their code as it runs. Both also "thunk" common libraries: a program's
call into, say, its OpenGL or SDL library goes to the host's native
arm64 library instead of a translated x86 copy.

**For fwe.** Neither applies to arm64 programs on an arm64 host. Library
thunking is Wine's idea applied selectively, and could in principle let a
guest use macOS libraries (Metal through a Vulkan or OpenGL library, say);
fwe does not do this.

### Rosetta 2

Rosetta 2 runs x86-64 macOS programs on Apple Silicon. It translates a
program ahead of time, when installed or first run, keeps the result in
a cache, and translates code made at run time as it appears. The
operating-system interface does not change: an x86-64 macOS program's
calls are macOS's. Apple also offers Rosetta inside Linux VMs, to run
x86-64 Linux programs there.

**For fwe.** fwe prepares a program's code (finds and rewrites its
system calls, thread-pointer accesses and `x18` uses) each time a
process maps it. Rosetta's cache is the model for keeping that work
between runs: a prepared image cached by the file's identity.

## A Linux personality in another kernel: FreeBSD's Linuxulator

FreeBSD runs Linux programs with the Linuxulator (`linux.ko`,
`linux64.ko`, on arm64 since FreeBSD 13). The kernel recognises a Linux
ELF at `execve` and gives the process a second system-call table; Linux
code runs natively, and its system calls go to `linux_*` functions in the
kernel that translate arguments, structures, errno values and signals to
FreeBSD's implementation. A Linux userland is installed under
`/compat/linux`, which path lookups try first, so a Linux program finds
its `ld.so` and libraries there; `linprocfs` and `linsysfs` provide
`/proc` and `/sys`. NetBSD's `compat_linux` works the same way; OpenBSD
removed its version in 2014; illumos had the same idea as "lx" branded
zones.

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

## Rebuilding for macOS: Homebrew and Nix

Homebrew and Nix build programs for macOS from source (or install builds
made so), so they run as macOS programs with no translation at all. That
is the fastest way to run what has been ported, and the right one where
it exists. What has not been ported (anything that needs namespaces,
cgroups, `/proc`, Linux's system calls: container runtimes, much server
software, Linux-only tools) cannot be had this way, and neither can a
given binary, such as a vendor's build or a container image. Nix builds
Linux packages on a Mac with a Linux VM (its `linux-builder`).

**For fwe.** fwe is for the other case: running the Linux build itself.
Homebrew is also how fwe is installed (`Formula/fwe.rb`).

## What fwe takes from each

- From **Wine**: native execution in-process, one host process per guest
  process, state shared between processes outside any one of them.
- From **FreeBSD's Linuxulator**: a Linux personality over the host's own
  services, and a separate Linux userland as the program's view.
- From **gVisor**: a Linux kernel as an ordinary program, and diverting
  system calls by patching the instruction into a jump.
- From **Noah** and **KVM** users: a VM with no kernel for what cannot run
  in-process.
- From **Rosetta 2**: the case for caching prepared code between runs
  (not yet done).
- From **WSL1**: the warning to measure fidelity, not assume it.
