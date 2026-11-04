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

- **The VM** (`vm.rs`). Its stage 2 is set up once, when the VM is made,
  and does not change while it runs: the slab (`window.rs`), all private
  guest memory, mapped whole, and fwe's own region (the page-table pool and
  a code page). Only shared segments add and remove mappings of their own.
  The framework keeps the host pages it found when a range was mapped, and
  the runtimes that run Linux programs this way without trouble
  (hyper-linux, elfuse) never change stage 2 or the host memory behind it
  either; nor does fwe.
- **The guest's page tables** (`pagetables.rs`). Stage 1 is real: 4 KiB
  pages, Linux's page size on arm64, in a 40-bit address space, with each
  page's EL0 permissions and BTI guarding. A guest page translates to the
  guest-physical address of its slab memory. Taking access away (unmapping,
  reducing permissions) bumps a generation; a vCPU resuming after that goes
  through the TLB stub on the code page (`tlbi vmalle1is; dsb ish; isb;
  eret`, at EL1), so every vCPU's TLBs are invalidated before the guest
  relies on the change, and memory given back is reused only after it.
- **Execution.** The guest runs at EL0. Every exception it takes enters the
  vector, which executes `hvc #2` (not `hvc #0`, which the framework may
  take for a firmware call), so the vCPU stops and the backend reads
  `ESR_EL1` to see what happened: an `svc` (a Linux system call, unchanged —
  nothing is rewritten, and `x18` and `TPIDR_EL0` are simply the guest's), a
  `brk`, an undefined instruction, an alignment fault, a translation or
  permission fault (`SIGSEGV`), a branch target exception (`SIGILL`).
- **Memory** (`mem.rs`). The kernel layer's memory system calls go to the
  backend (`Platform::memory`), which keeps the guest's mappings
  (`crates/kernel/src/vmas.rs`) and edits the page tables; host memory is
  never replaced behind the VM. Private memory is slab memory: a mapping the
  guest did not place sits at the same address as guest and host address; one
  it placed outside the slab (the executable's image at its low link
  address, a `MAP_FIXED` address) is backed by slab memory elsewhere and
  translated, as the kernel's checked copies, the pointer arguments it hands
  to host calls and `iovec`s do through a table of translated ranges
  (`crates/kernel/src/uaccess.rs`). A private file mapping is a copy of the
  file's data. Shared memory (`MAP_SHARED`, of a file, or anonymous, then of
  an unlinked file) is a *segment*: a host mapping outside the slab, mapped
  into the VM once. The host's memory behind the guest stays accessible where
  the guest's is not, so every guest pointer the kernel or the host is given
  is checked against the guest's mappings first (`EFAULT`). Code fwe writes
  into guest memory (images, file data, a fork child's memory) has the
  instruction cache invalidated, as Apple's cores do not keep it coherent
  with data writes.
- **Pointer authentication and BTI**, where the VM offers them (its vCPUs'
  ID registers say): enabled in `SCTLR_EL1` as Linux enables them; each
  program gets random keys, a thread its creator's, a fork child its
  parent's, `PR_PAC_RESET_KEYS` new ones; `AT_HWCAP` reports `PACA` and
  `PACG`. Code of a program built for BTI is mapped `PROT_BTI` where Linux
  maps it so (the interpreter, or a static program), and a signal handler is
  entered as from `blr`.
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

A fifth crash, the same day at 16:03:48, came during a deliberate,
fully recorded real run (the flight recorder, below, synced to disk). The
record shows the map-rules probe agreeing with the stand-in, then the fork
tests: 19 fork children and 3 vfork children that exec'd all ended cleanly.
The last lines are a glibc `posix_spawn` vfork child, which had mapped the
parent's writable memory *shared* into its own VM (its spawn stack
included), failing its `execve` as the test intends, destroying its VM and
exiting; 5 ms later the parent took that same stack out of its own VM and
mapped one more range — and nothing was ever written again. Crash 4 also
followed vfork children with shared memory. The path inside the kernel is
still unknown, but the runtimes that run Linux programs on Apple Silicon
the same way without such reports (hyper-linux, elfuse, Carrick) all avoid
what fwe does here: they map guest memory into the VM once and never
change stage 2 or the host memory behind it while the VM runs (guest
`mmap`/`munmap`/`mprotect` only edit the guest's page tables), they give a
fork child a copy-on-write copy rather than pages mapped into both VMs,
and none maps a vfork child's memory into a second VM. The backend's
memory model is being reworked to match.

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
backend. Two differences from Linux remain: a private file mapping is a copy
of the file when it was mapped, so later writes to the file through other
mappings or descriptors do not show in it; and what a `vfork` child changes
in its address space itself (`mmap`, `munmap`, `mprotect` before it execs or
exits) stays its own — the memory it writes reaches the parent, its mapping
changes do not.

## Fork

The child of a `fork` or `vfork` in the VM is a fresh fwe process,
`fwe --hv-fork-child`, started with `posix_spawn` — never a host fork. It
reserves the slab at the parent's address, takes the parent's memory records
and kernel state (through a receive right the parent gave it as its
bootstrap port, with the real bootstrap port), rebuilds the kernel (and the
kqueues behind `epoll` and `timerfd`, which no child inherits), makes its own
VM and fills its page tables from the records, and resumes after the `svc`
with `x0` = 0. No private page is ever in both processes' VMs:

- a **`fork`** child is sent a copy of every page of the slab that exists
  (`mach_vm_page_range_query`), over a socket pair, with the parent's vCPUs
  stopped so it sees one instant. Copying 512 MiB takes about 60 ms; an APFS
  clone of a file-backed slab, which elfuse uses, was measured fifty times
  slower here, as it writes the memory to disk;
- a **`vfork`** child is sent nothing up front: its private pages are
  unmapped until it touches them, when it fetches them, 64 KiB at a time,
  from the parent, whose waiting thread serves it (a guest pointer the
  kernel or the host is given is fetched first too). Before it execs or
  ends it sends back the bytes it changed, compared with what it fetched, and
  the parent resumes once they are in its memory — so what the child writes
  the parent sees, as on Linux, without either VM mapping the other's pages;
- shared memory goes to the child as its file, which the child maps: those
  pages are in both VMs, as Linux shares them.

See [architecture.md](architecture.md#processes) for the state carried over.

## The stand-in

`fwe --hv-standin` runs the backend on a software stand-in for
Hypervisor.framework (`crates/native/src/hv/standin.rs`): every framework
call the backend makes goes to an emulated CPU instead, Unicorn (QEMU's CPU
emulator as a library, `brew install unicorn`), loaded only in this mode. It
creates no VM, so it is safe on any Mac and runs in hosted CI; the flag is
passed on to every fwe a guest's `execve`, `fork` or `vfork` starts.

It models what the backend relies on: one VM per process and one vCPU per
thread; stage 2 as exactly the memory mapped with `hv_vm_map`, with its
flags; stage 1 as fwe's own tables, walked as the hardware walks them (a
translation or permission fault, with its level and address, where the
tables say), cached by the emulated CPU until fwe's TLB stub runs, which it
carries out (only that stub may run at EL1); exceptions at EL0 going through
the vector to `hvc #2` with `ESR_EL1` and the other EL1 registers set, and
direct exits for stage-2 aborts, `wfi`/`wfe` and the physical counter;
`hv_vcpus_exit` from any thread or signal handler; pointer authentication,
with the keys fwe sets (QEMU's CPU signs and authenticates, run Non-secure
as a VM runs, since QEMU traps the instructions in Secure state); BTI
landing pads on guarded pages, which it checks itself, as its TLB hook
cannot mark a page guarded for QEMU — and QEMU sets `BTYPE` as for a branch
from an unguarded page, so a `br` through a register other than x16 or x17
also accepts `bti c` or `paciasp`. Only one vCPU emulates at a time, handed
on at the next block whenever another waits, and each emulated CPU is driven
only by its own thread: Unicorn's API, `uc_emu_stop` included, races with an
engine running on another thread (on Apple Silicon every call updates the
engine's JIT write-protection bookkeeping unsynchronised), which lost guest
register updates; and Unicorn runs hooks inside its own memory calls, so no
lock a hook takes is held across them. Emulation is several times slower
than the CPU, so the tests give a guest on the stand-in a longer time limit.

And it checks the rules the backend must keep, printing a line with
`fwe hv stand-in: VIOLATION:` on which the tests fail:

- a vCPU used from a thread other than its own, a VM destroyed with vCPUs
  alive, a vCPU run before its translation regime is set (40 bits, 4 KiB
  granule) or at EL1 anywhere but the TLB stub;
- a vector that is not `hvc #2` at each entry;
- a change to the stage 2 the VM ran with (anything but shared segments);
- host memory behind stage 2 replaced while the VM maps it (its VM object
  changed), checked now and then;
- anonymous host memory behind stage 2 shared with another process (pages
  in two VMs: a file's shared pages are what `MAP_SHARED` means);
- through a watcher process started with the VM, a process that ends or
  execs with its VM alive.

A refused `hv_vm_map` is reported too, and fails as the framework fails it:
misaligned (16 KiB), overlapping, or over host memory that is not mapped or
could never be readable and writable. That last rule was inferred from what
the framework did, and a real run's `--probe hv-map-rules` matched it. The
stand-in's unit test breaks each rule on purpose.

A stand-in proves nothing about the real framework. Its own rules are what
fwe has seen the framework do, and the kernel crashes the backend may cause
cannot happen in it. So VM changes are also run on real hardware now and
then, on a machine whose crash costs nothing, instrumented so that a crash
can be traced (below). Not modelled: the virtual timer, the fault address of
an alignment fault outside the exclusive and atomic instructions,
stack-pointer alignment checks, and code one vCPU writes for another
without a mapping change. What real hardware must still confirm for this
memory model: the 4 KiB stage-1 granule on every M-series chip, pointer
authentication and BTI as the vCPUs' ID registers offer them, and how the
framework treats cache maintenance and `dc zva` at EL0 (hyper-linux reports
traps: `HCR_EL2.TPU`, `TDZ`). `FWE_STANDIN_DEBUG=1` reports each exception
and exit it models.

## Real-hardware runs and the flight recorder

Real runs happen on a machine whose crash costs nothing — the self-hosted
runner of the `hypervisor` CI job, such as a rented bare-metal cloud Mac —
and are instrumented so that a crash can be traced. The crashes so far were
watchdog resets that left no stackshot and lost the last seconds of the
system log, so the evidence has to be kept by fwe itself:

- **The flight recorder** (`--hv-record DEST`, or `FWE_HV_RECORD=DEST`; in
  `crates/native/src/hv/record.rs`) writes a line before and after every
  framework call that changes a VM — `hv_vm_create`, `hv_vm_map`,
  `hv_vm_unmap`, `hv_vcpu_create`, `hv_vcpus_exit`, `hv_vcpu_destroy`,
  `hv_vm_destroy` — with its arguments and result, each process's start,
  `execve`, fork children and end (exit status or signal), and a heartbeat
  with the count of `hv_vcpu_run` calls every half second. Each line is
  written synchronously: to `file:PATH` with `F_FULLFSYNC`, so it is on the
  disk before the call it announces, and/or to `udp:HOST:PORT` as a datagram
  to another machine, which a reset cannot take back; there
  `tools/hv-record-listen.py PORT` collects them. The setting reaches every
  fwe a guest starts. A call begun and never ended names what was running
  when the machine went down.
- **The `hypervisor` job** records every run to a file outside its
  workspace (and to `FWE_HV_RECORD_UDP`, a repository variable, if set),
  marks the record finished at the end, and at its start reports any
  earlier record that never finished, with its last lines, alongside the
  boot time and the panic reports — so the run after a crash shows what the
  crashed one was doing. The record is also kept as a job artifact.
- **The stand-in's inferred rules are checked**: the job runs
  `fwe --probe hv-map-rules` on the framework and on the stand-in, and fails
  if the framework maps host memory the stand-in would refuse, or the other
  way round.

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
bare-metal cloud Mac, never the development Mac. Install Unicorn there too
(`brew install unicorn`, which the job also does) for the probe comparison,
and make sure the runner service's `PATH` includes Homebrew
(`/opt/homebrew/bin`), as it does not by default.
To have the record streamed off the machine, run
`tools/hv-record-listen.py PORT` on a machine that can receive from it and
set the repository variable `FWE_HV_RECORD_UDP` to `udp:HOST:PORT`.
