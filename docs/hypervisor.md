# The hypervisor backend

Some Linux binaries are **non-PIE `ET_EXEC` executables linked at a fixed low
address**: Debian's `/usr/bin/python3.11` at `0x400000`, static Go at
`0x10000`, anything a toolchain links without `-pie`. The native backend
cannot run them. macOS gives every arm64 process a mandatory 4 GiB
`__PAGEZERO`, enforced as the minimum address of the process's map, so the
address the binary needs is unmappable, and a non-PIE image has no relocation
information to move it elsewhere. This is an OS limit, not an implementation
gap: Apple's loader refuses a smaller `__PAGEZERO` on Apple Silicon, and
other emulators hit the same wall.

A hardware VM sidesteps it: the guest gets an address space of its own with no
`__PAGEZERO`. On macOS the userspace API for one is **Hypervisor.framework**,
which needs the `com.apple.security.hypervisor` entitlement but no root — an
ad-hoc signature carrying the entitlement is enough. fwe picks this backend
automatically for an executable it cannot map in-process.

## How it works

The code is in `crates/native/src/hv/`.

- **The VM** (`vm.rs`). A 40-bit guest-physical address space. Stage 1 maps
  it all as identity 32 MiB blocks of normal memory accessible to EL0, so it
  never faults; what the guest may touch, and how, is decided at stage 2 by
  which host memory is mapped where, with the guest's protections. The top
  block holds fwe's page tables and an exception vector, mapped for EL1 only.
- **Execution.** The guest runs at EL0. Every exception it takes enters the
  vector, which executes `hvc #0`, so the vCPU stops and the backend reads
  `ESR_EL1` to see what happened: an `svc` (a Linux system call, unchanged —
  nothing is rewritten, and `x18` and `TPIDR_EL0` are simply the guest's), a
  `brk`, an undefined instruction, an alignment fault. An access to memory the
  guest has not mapped stops the vCPU with a stage-2 abort, which becomes
  `SIGSEGV`.
- **Memory.** Guest memory is host memory mapped into the VM. Everything the
  guest maps itself — stack, break, `mmap`s, the dynamic linker and the
  libraries it loads — is placed at the same address in the VM as in the
  host, so guest pointers are host pointers, as in the native backend. Only
  the executable's image, at the low address the host cannot map, lives
  elsewhere in the host: that one range is registered with the kernel layer,
  which translates guest pointers into it wherever it uses them — in its
  checked copies of guest memory (`crates/kernel/src/uaccess.rs`), in the
  pointer arguments it hands to host system calls (a table of which arguments
  are pointers), and in `iovec`s. The kernel's memory system calls tell the
  backend about every mapping change (`Platform::map_guest` and friends), so
  the VM's view follows the host's.
- **The kernel.** System calls go to the same kernel layer as the native
  backend's, through a `Platform` of the backend's own.
- **Signals.** As in the native backend, guest dispositions are mirrored onto
  the host and the vCPU thread runs under the guest's mask. The handler
  records the signal and stops the vCPU (`hv_vcpus_exit`), and the run loop
  delivers it — so a signal reaches a guest busy in a loop without system
  calls too. The framework's own threads are created with every guest signal
  blocked, so the host never hands one to them.

- **Threads.** Each guest thread is a host thread with a vCPU of its own,
  created on it; all vCPUs share the VM.
- **`execve`** re-executes fwe on the new program (as the native backend does
  for a program only the VM can run). The fresh fwe picks the backend the
  program needs, so a program in the VM can exec a native one and the other
  way round; the host keeps across its exec what Linux keeps across
  `execve` — the pid, descriptors not marked close-on-exec, the signal
  mask — and the root, working directory and `--strace` are passed on.

## Never end a VM process abnormally

On 3 November 2026 the development Mac (macOS 15.6.1, M4 Pro) went down twice
while this backend was being built: a watchdog reset about two minutes after a
VM process was killed by a signal, and a kernel panic (a NULL dereference in a
kernel thread) while a VM process was being torn down. Neither was memory
pressure. Both times the VM processes ended without destroying their vCPUs and
VM, the tests ran several of them at once, and another Hypervisor.framework
client (Podman's `krunkit`) was running.

It went down a third time that day, with a watchdog reset at about 16:18,
and that time no fwe VM was alive: the last VM test (the fork tests) had
ended cleanly 23 minutes before, and the one fwe run just before the crash
failed before creating a VM. Before that day the machine had been up for
three weeks with `krunkit` (which uses nested virtualization) running, so
the crashes follow this backend's use of the hypervisor, but can come long
after it. That points to kernel state left behind rather than the moment of
teardown; the panic of the second crash, in a kernel thread, lands near the
kernel's thread-destruction code. The exact path is Apple's, and the panic
reports are too thin to show it, so the backend rules out everything on its
side of it.

It went down a fourth time on 4 November at about 13:47, again a watchdog
reset with no stackshot, and this time with no other hypervisor client
running: `krunkit` had been stopped three and a half minutes before. Eight
VM tests had passed one at a time, then for a minute a `vfork` test and four
runs of one of its scenarios each started a child whose VM could not map
the parent's read-only code (`hv_vm_map` failed, since a shared memory entry
of read-only memory carries no write permission), which tore its VM down and
exited. The crash came 30 to 40 seconds after the last of them, with nothing
about fwe or the hypervisor in the system log. So `krunkit` running
alongside is not needed for a crash, and a VM that fails to map memory and
is then destroyed joins the suspects.

Since then **a plain `cargo test` never starts a VM**: the VM tests run on
a software stand-in for the framework (below), and on the real one only when
asked for (`FWE_HV_TESTS=1`), which only a machine whose crash costs nothing
should set. Everything else the backend does to stay clear of the crash:

- **Every way out tears the VM down first:** `exit_group`, the last thread's
  `exit`, a fatal signal's default action, fwe's own fatal errors, faults and
  panics, and `execve`. Teardown stops every vCPU, has each thread destroy its
  own (the framework requires that), then destroys the VM.
- **Signals whose default action terminates are caught** in the VM backend,
  so the process dies through that teardown, never by the host's default
  action with the VM alive. `SIGKILL` cannot be caught, so a guest's
  `SIGKILL` to an fwe process (`kill`, `tgkill`, to a process, a group or
  everyone) is sent as `SIGINFO`, which has no Linux counterpart: a VM
  process takes it as the guest's `SIGKILL`, tears down and then dies of
  `SIGKILL`, so its parent sees the status Linux gives. Only a `SIGKILL`
  from outside fwe cannot be intercepted.
- **No host `fork` of a VM process.** A fork child cannot use the parent's VM
  — `hv_vm_destroy` fails there with `HV_NO_DEVICE` and `hv_vm_create` with
  `HV_BUSY` — so it would die with a VM it inherited.
  `fwe_kernel::fork_locked` refuses outright once a VM exists. A guest's
  `fork` and `vfork` start a fresh fwe process instead (below), which builds
  a VM of its own and keeps to these same rules; a fork child that fails to
  set up tears down any VM it made before it exits.
- **The VM lets go of memory before the host changes it.** `munmap`, a
  shrinking `mremap`, a `MAP_FIXED` mapping over existing memory and
  `MADV_DONTNEED` remove the range from the VM before the host frees or
  replaces the memory behind it, and map it again afterwards where needed,
  so the VM never maps memory the host is freeing.
- **The tests run one VM test at a time**, never several in parallel. A test
  of `fork` has the parent's and the child's VM processes alive together,
  as any forking program does; each ends through teardown, a guest's
  `SIGKILL` included. Each VM test's processes form a process group: a
  timeout sends it `SIGTERM` (caught, so every VM is torn down) and only a
  group still alive 5 s later gets `SIGKILL`, and a process outliving its
  test fails that test.
- **Never alongside another hypervisor client.** The VM tests skip while one
  runs (`krunkit`, `vfkit`, QEMU, Virtualization.framework VMs and the
  like); for Podman, `podman machine stop` first. The same goes for running
  a VM program by hand.

Keep to these when changing the backend.

## Status

Programs linked below 4 GiB run in the VM, static and dynamically linked, with
threads: the assembly test programs, Rust/musl programs, and a non-PIE glibc
program whose own `ld.so` maps `libc.so.6`, relocates and applies RELRO — the
shape of Debian's `python3.11`. They can `execve` any program, and a native
program can `execve` them, and `fork` and `vfork` work as in the native
backend. A memory call (`mmap` with a fixed address,
`munmap`, `mprotect`, `madvise`, `mremap`) on a range that runs across the
edge of the executable's image fails with `EINVAL`, since that range has no
single host address.

## Fork

The child of a `fork` or `vfork` in the VM is a fresh fwe process,
`fwe --hv-fork-child`, started with `posix_spawn` — never a host fork. All
guest memory lives in one reserved host address window (512–960 GiB, inside
the VM's 1 TiB address space), so the child can map it at the same
addresses. With every other vCPU stopped, the parent takes a Mach memory
entry per region: a copy-on-write snapshot of private memory, a share of
`MAP_SHARED` memory (and of everything, for a `vfork` child). A snapshot is cheap (about 2 ms for 1 GiB) and neither
process pays for a page until one of them writes to it. The entries, the
real bootstrap port and the encoded kernel state reach the child in one Mach
message, through a receive right the parent gave it as its bootstrap port.
The child maps the memory, rebuilds the kernel (and the kqueues behind
`epoll` and `timerfd`, which no child inherits), creates its own VM over the
same guest mappings and resumes after the `svc` with `x0` = 0. See
[architecture.md](architecture.md#processes) for the state carried over.

## The stand-in

`fwe --hv-standin` runs the backend on a software stand-in for
Hypervisor.framework (`crates/native/src/hv/standin.rs`): every framework
call the backend makes goes to an emulated CPU instead, Unicorn (QEMU's CPU
emulator as a library, `brew install unicorn`), loaded only in this mode. It
creates no VM, so it is safe on any Mac and runs in hosted CI; the flag is
passed on to every fwe a guest's `execve`, `fork` or `vfork` starts.

It models what the backend relies on: one VM per process and one vCPU per
thread; stage 2 as exactly the memory mapped with `hv_vm_map`, with its
flags; stage 1 as fwe's own tables, read from guest memory at the first run
and checked to be the identity; exceptions at EL0 going through the vector
to `hvc` with `ESR_EL1` and the other EL1 registers set, and direct exits for
stage-2 aborts, `wfi`/`wfe` and the physical counter; `hv_vcpus_exit` from
any thread or signal handler. Only one vCPU emulates at a time, handed on
every few milliseconds.

And it checks the rules the backend must keep, printing a line with
`fwe hv stand-in: VIOLATION:` on which the tests fail: a vCPU used from a
thread other than its own, a VM destroyed with vCPUs alive, a vCPU run
before its translation regime is set or leaving EL0, and — through a
watcher process started with the VM — a process that ends or execs with its
VM alive. A refused `hv_vm_map` is reported too, and fails as the framework
fails it: misaligned (16 KiB), overlapping, or over host memory that is not
mapped or could never be readable and writable. That last rule is inferred,
not documented: the framework mapped memory whose most was RWX or RW
(executable included) but refused a `vfork` child's shared code, which
could only ever be read. The stand-in reproduces that failure.

A stand-in proves nothing about the real framework. Its own rules are what
fwe has seen the framework do, and the kernel crashes the backend may cause
cannot happen in it. So VM changes are also run on real hardware now and
then, on a machine whose crash costs nothing, instrumented so that a crash
can be traced. Not modelled: the virtual timer, the fault address of an
alignment fault outside the exclusive and atomic instructions, stack-pointer
alignment checks, and code one vCPU writes for another without a mapping
change. `FWE_STANDIN_DEBUG=1` reports each exception and exit it models.

## Running it (Apple Silicon, no root)

```sh
cargo build --release -p fwe
codesign --sign - --entitlements hypervisor.entitlements --force target/release/fwe
target/release/fwe ./program-linked-low
```

Without the entitlement, or on a host without hypervisor support, fwe
explains that the program needs the hypervisor backend and exits with status
126. `fwe --hv-spike` runs a tiny guest in a VM — a quick check that the
hypervisor works on a machine: it prints `hv: hello from the guest` and
reports the status 42 the guest exits with. `sysctl kern.hv_support` must be
`1`.

## Tests and CI

The end-to-end tests whose names start with `hv_` run low-linked programs in
the VM backend. By default they use the stand-in, with the unsigned `fwe`,
which could not create a real VM even by mistake (the tests check it carries
no entitlement). With `FWE_HV_TESTS=1` they sign a copy of `fwe` with the
entitlement and use the real framework, one test at a time. Where neither
can run (no Unicorn; no hypervisor), they report that they were skipped and
pass.

GitHub's hosted macOS runners are themselves virtual machines without nested
virtualization, so Hypervisor.framework is unavailable there. This is
measured, not assumed — the `macos` jobs run an informational step that
reports it:

- `macos-15`: `kern.hv_support` OID does not exist.
- `macos-26`: `kern.hv_support: 0`.
- Both: `hv_vm_create` returns `0xfae9400f` (`HV_UNSUPPORTED`), even though the
  binary is correctly signed with the entitlement.

So in hosted CI the backend's tests run on the stand-in, and on the real
framework only on a **self-hosted Apple Silicon runner**, in the
`hypervisor` job.

### Registering the self-hosted runner (one time)

On an Apple Silicon Mac (bare metal, not a VM), confirm `sysctl
kern.hv_support` is `1`, then register it as a repository runner:
`Settings → Actions → Runners → New self-hosted runner`, choose macOS/ARM64,
and follow the shown `./config.sh` / `./run.sh` steps. GitHub labels it
`self-hosted`, `macOS`, `ARM64` automatically. Install a Rust toolchain for
the runner user (`rustup`) and the Xcode command line tools (`clang`).

Then set the repository variable that enables the job:
`Settings → Secrets and variables → Actions → Variables → New variable`,
name `FWE_HV_SELF_HOSTED`, value `true`. The job stays skipped until this is
set, so it never blocks PRs when no runner exists. Once set, it runs the
`hv_` end-to-end tests (with `FWE_HV_TESTS=1`) and `fwe --hv-spike` on every
push.

The runner should be a machine whose crash costs nothing, such as a rented
bare-metal cloud Mac, never the development Mac.
