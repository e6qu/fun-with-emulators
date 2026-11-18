# Code made at run time

## Summary

A JIT compiler (HotSpot's, V8's, LuaJIT's, Racket's, Guile's) writes
machine code into memory as the program runs and then runs it. So do
self-modifying programs, code built on the stack, and Wine loading
Windows code. fwe cannot prepare such code the way it prepares a file's
code ([linux-on-macos.md](linux-on-macos.md#which-instructions-get-translated-and-how)):
it does not exist when the program is loaded, and the program keeps
writing, patching and copying it. Natively, fwe runs it by
**translation**: when the program jumps to code it made, the block
there is translated into fwe's own code cache and run from there, and
the program's memory stays exactly as the program wrote it. In the VM
backend, code made at run time runs as it is: the guest's `x18` and
system calls are its own there.

This document holds why fwe translates such code, how translation works
and what the program sees, how fwe learns that code changed, what it
costs, which runtimes it is tested with, and how other translators solve
the same problems. The current limitations are in
[architecture.md](architecture.md#known-limitations), and the code is
`crates/native/src/jit.rs`.

## Why translation

A JIT keeps more than code in its code pages: headers, constants and
addresses beside the instructions (HotSpot its code blobs' headers and
trampolines' targets, V8 its metadata and compressed pointers). It reads
that memory back, patches calls and constants in place, copies code
from a buffer to its final place, and walks stacks of return addresses
into it. macOS has no memory that can be run but not read, so any
instruction fwe rewrote in place there would be seen, and could be
copied, compared or patched over by the program.

So fwe changes nothing in that memory and never lets the host run it.
Memory the program makes executable after mapping it (`mprotect` adding
`PROT_EXEC`), maps writable and executable at once, or maps from a file
shared and open for writing (a memfd a JIT maps twice) is mapped on the
host readable and never executable. Only code that runs is decoded,
following the program's control flow, so nothing has to tell code from
data. Rosetta 2 and DynamoRIO run code generated at run time the same
way.

## How it runs

- **The fetch faults.** A jump into such memory faults, and fwe
  translates the block of code at that address into its code cache and
  goes on there. A block is at most 64 instructions and ends at a
  branch out, at an `isb` and at its page's end.
- **The translation** holds the program's instructions as they are,
  except those whose meaning depends on where they are or that macOS
  does not let a program run unchanged: `adr`, `adrp` and literal loads
  are computed from the program's address; uses of `x18`, system calls,
  thread-pointer accesses and instruction cache flushes are expanded as
  their stubs are, inline; branches out of the block go to translations.
- **Branches.** A direct branch goes through fwe the first time and is
  then linked: straight to its target's translation, or to code that is
  not translated (a runtime's helper a JIT calls with `bl`) straight
  there where a branch reaches, otherwise through a veneer that loads the
  target into `x16`, as a linker's veneer does (the procedure call
  standard lets one clobber `x16` and `x17` on a direct branch to other
  code). A `cbz` or `tbz` of `x18` tests the program's `x18` inline. A
  call puts the program's own return address in `x30`, so the stack
  holds only the program's addresses. An indirect branch or a return
  looks its target up in a table of translations by program address,
  `x16` and `x17` saved for the lookup; the translation it reaches checks
  that the target is its own (an entry can be taken over or dropped while
  a lookup reads it), then restores them. A miss goes through fwe once
  and fills the table. An indirect branch or return into code that is
  not translated (a library's, prepared in place) restores `x16` and
  `x17` and is made through the program's own register, so every
  register is as the program left it: code may count on more than the
  procedure call standard promises (HotSpot calls its atomic stubs
  saying they clobber only `x8`, `x9` and `x30`, and keeps values in
  `x16` across them). One through `x18`, or a call through `x30`, takes
  fwe's trap.
- **Code a translation calls is translated too.** A runtime's helpers in
  its library, the C library, the program's own functions: code fwe
  prepared in place that a translation calls or branches to runs from
  translations as well, read as the program wrote it (each instruction
  fwe rewrote taken from the record of what it was), so what it calls and
  where it returns stay in translations: a C helper's return into a
  JIT's code is a lookup, not a fault. A return is followed only to
  where a translated call returns; one to a caller that runs as it is
  (the code that called into the JIT's) goes back there. The same code
  keeps running as it is wherever it is called from code that is not
  translated.
- **Calls into translated code.** Native code's call into a JIT's code
  faults the first time; that call site (`blr`) becomes a `bl` to a stub
  in reach that looks the target up as a translation does, and goes to
  its translation, so the next calls fault no more.
- **What the program sees stays its own.** Its memory reads back exactly
  as it wrote it. A fault or signal in a translation is delivered at the
  program's instruction, with its registers: an expansion stopped before
  its instruction ran is undone, one stopped after is finished. A system
  call made from a translation is the program's `svc`'s: a tracer stops
  there, a handler's frame holds it, and a restarted call is made again
  from it. A signal delivered as a thread goes on into a translation
  gets a frame with the program's state too.
- **The code cache** is made of 128 MiB chunks (what a branch reaches),
  each mapped twice, writable for fwe and executable for the threads
  that run it. A full chunk is followed by a new one, or, when at least
  half of the cache holds translations dropped since, the cache is
  emptied with every other thread stopped, keeping aside the translations
  a thread may still be in or return into; the code is translated again
  as it runs. A fork child gets its own copy of the cache.

## Code that changes

### Why a program flushes the instruction cache

An arm64 core fetches instructions through an instruction cache of its
own, beside the data cache its loads and stores go through. A store of
new code lands in the data cache; the instruction cache may still hold
the old instructions at that address, and the core may run them. So the
architecture has a program that writes code make it visible before it
runs it, with three steps for each cache line it wrote (the line sizes
are in `CTR_EL0`: 64 bytes on Apple's processors):

```
dc   cvau, x0     // data cache: clean the line to the point of unification
dsb  ish          // wait until that is done, for every core
ic   ivau, x0     // instruction cache: invalidate the line
dsb  ish          // wait until that is done, for every core
isb               // this core: fetch what follows afresh
```

- **`dc cvau`** ("data cache clean by virtual address to the point of
  unification") writes the line out of the data cache to the level
  where instruction fetches and data accesses meet, so a fetch can see
  it.
- **`ic ivau`** ("instruction cache invalidate by virtual address to
  the point of unification") discards the line from the instruction
  caches, of every core in the inner shareable domain, so the next fetch
  there reads the new code. User code may run it (Linux and macOS
  allow it at EL0). It names an address, but the instruction cache the
  `CTR_EL0` fwe gives describes is physically indexed and tagged (PIPT,
  as Apple's is), so it works on the memory behind the address: a flush
  through any mapping of that memory flushes them all.
- **`dsb ish`** waits for the maintenance to finish everywhere, and
  **`isb`** has this core drop instructions it has already fetched.
  Another core that runs the new code needs an `isb` (or another
  context synchronization, such as an exception's return) of its own.

`__clear_cache` (GCC's `__aarch64_sync_cache_range`, LLVM's
compiler-rt), and each JIT's own routine (HotSpot's
`ICache::invalidate_range`, V8's `FlushInstructionCache`, LuaJIT's
`lj_mcode_sync`), run this sequence over the range written. A processor
may report in `CTR_EL0` that it needs part of it no more: `IDC` set,
the clean is not needed; `DIC` set, the invalidation is not needed, and
these routines skip it. The value fwe gives a program that reads
`CTR_EL0` is Apple's under Linux, with both clear
([linux-on-macos.md](linux-on-macos.md#ctr_el0-emulated-when-it-traps)),
so a program that writes code always runs `ic ivau` over it.

### What fwe does with it

fwe takes that flush for the word that the code changed:

- **`ic ivau` calls fwe.** In code prepared in place it is a site whose
  stub runs the instruction and calls the system-call gate; a
  translation expands it the same way. The gate drops the translations
  made from that cache line (64 bytes), and the code is translated again
  when it next runs. A translation running when its code is flushed
  goes on to its end: the `isb` that follows a flush ends a block, so
  code that rewrites instructions just ahead of itself runs the new ones.
- **The rest of the memory is the program's.** Nothing else it writes
  costs anything: a JIT's data beside its code, a constant patched, a
  trampoline's target changed.
- **Through any mapping.** A JIT that maps its code twice (a memfd,
  writable and executable) may flush either view, since both are the
  same memory: a flush through either drops the translations made from
  it.
- **Taken back if unchanged.** A block a flush dropped is kept with the
  words it was made from; when its address runs again and the words are
  unchanged (a method installed again where it was), the block is
  taken back instead of translated anew.
- **Other changes.** Mapping memory anew, unmapping it, changing its
  protections and giving it back (`MADV_DONTNEED`) drop its translations
  too, as does a write fwe makes into code itself (a debugger's
  breakpoint through `ptrace` or `/proc/<pid>/mem`, after which Linux
  syncs the instruction cache).

What this does not see is code a program changes without flushing it,
or that another process writes into it other than through its tracer:
the old translation keeps running, as stale instructions may on Linux on
a processor that reports `DIC` clear.

## Inside

- **Entry:** `on_fault` passes an instruction fetch fault to
  `jit::enter`, which translates the block (`jit::translate`) and
  resumes the thread in it. A new block's direct ways out are linked to
  targets already translated, and ways out waiting for it to it
  (`jit::link_waiting`).
- **Ways out:** a block's way out (a direct branch's, or a lookup's
  miss) saves `x16` and `x17` below `sp` and branches to the exit gate
  (`gate::fwe_exit_gate`) with its own address in `x16`; the gate saves
  the program's registers in the thread's block, as the system-call gate
  does, and calls `jit::gate_exit` without a signal: the target is
  translated and the branch patched to it (linked, within a chunk), and
  the gate enters that translation as a lookup does. Anything else (code
  not translated, a signal to deliver) takes the gate's `brk`, whose
  handler goes on from the block. A way out unlinked again when the
  cache is emptied is `brk #0x4a54` (`jit::EXIT`), which `on_sigtrap`
  passes to `jit::exit`. A direct branch's target that is code not
  translated is patched to it where a branch reaches, else to a veneer
  block (`jit::veneer`: the target in `x16`, `br x16`). A `cbz`/`tbz` of
  `x18` loads the guest's `x18` into `x16` (saved with `x17` as a lookup
  saves them) and tests it there.
- **The table** of translations by guest address is 2^20 entries of
  (address, translation) at 2^45 (32 TiB, reachable with one `orr`),
  its place taken as fwe starts (`jit::configure`), before the program
  maps anything that could take it. A target outside run-time code (a
  library's) gets entry 0. A dropped entry reads as a retry stub at the
  first chunk's start.
- **The code cache's views:** each chunk is mapped twice with
  `mach_vm_remap`, written through the writable view and run from the
  executable one; `jit::in_cache` tells a cache address without a lock.
- **Following:** an exit to code fwe prepared in place
  (`jit::followable`: in an executable mapping of the guest's, not a
  stub) is translated as well, except a return, followed only to the
  return point of a translated call (`State::returns`). Such code is
  read through `prepare::original`, which gives back the instruction at
  a site from the sites recorded as stubs were made (`prepare::SITES`),
  checked against the stub's branch back.
- **Call sites:** a fetch fault whose `x30` follows a `blr xN` in code
  prepared in place links that site (`jit::link_call_site`): with every
  other thread stopped, a stub doing the table lookup goes in the spare
  page every stub region and loader arena keeps (`prepare::call_stub`),
  and the `blr` becomes a `bl` to it.
- **Guest state:** each translated word records what it stands for
  (`Word`: the guest instruction, a point inside an expansion before or
  after its instruction, a lookup, a way out), so `jit::to_guest` turns
  a fault, signal, system call or tracer stop there into the guest's
  state at its instruction: an expansion is undone (`undo`, reading back
  what it pushed) or finished (`finish`, `step`, carrying out its
  remaining words).
- **Flushes:** the `ic ivau` stub (`rewrite::flush_stub`) runs the
  instruction (but through `x18`, whose value only the gate knows, which
  the gate invalidates itself) and calls the gate as a system call's
  stub does. The gate tells the two apart by the stub's load of its
  address (`rewrite::flush_reg`) and calls `jit::flushed`, which drops
  the blocks made from that line (`jit::drop_lines`): it unpublishes
  their entries and re-patches the branches linked to them into ways
  out. The other mappings of each file page code was translated from
  are noted as that code is first translated (`jit::note_aliases`) and
  as new mappings appear (`jit::mapped`), so a line flushed through one
  drops those of the page translated from. Dropped blocks are kept in
  `State::dormant` and taken back by `jit::revive`. The kernel tells
  the backend of the other changes (`Platform::jit_changed`,
  `jit_discarded`, and `procmem::on_code_written` for its own writes).
- **Emptying:** when the current chunk is full and dropped or retired
  translations are at least half the cache, `jit::flush` stops every
  other thread (`quiesce::stop_others`) and scans their registers, 2 MiB
  above each `sp` and the gate blocks for cache addresses: the blocks
  found are retired (kept, found by no lookup, never linked), and each
  chunk holding no retired block is reused. Otherwise a new chunk is
  added, up to 64 (8 GiB).
- **Fork and exec:** `fork` holds the translator's lock (`jit::hold`),
  and the child maps each chunk's executable view again from its own
  copy of the writable one (`jit::forked`); an in-place `execve` drops
  every translation (`jit::reset`).
- **One lock:** the translator's state is behind one lock, taken to
  translate, to link a way out, to drop a flushed line and to enter by
  a fetch. Lookups and linked branches take none.

## What it costs

| Event | Cost | How often |
|---|---|---|
| a block's first run | a fault and a translation | once per block, and again after a flush that changed it |
| a direct branch's first run | a call through the exit gate | once per branch, then linked |
| an indirect branch or return | an inline table lookup, a few instructions | each time; a miss goes through the exit gate |
| a call from native code into JIT code | a fault | once per call site, then linked |
| `ic ivau` | a call through the gate | each cache line the program flushes |
| anything else the program writes | nothing | |

`FWE_TIMING=1` prints, as a process exits, what its translations cost:
blocks translated, ways out taken through fwe and the time spent in
them, entries by fetch, cache lines flushed and blocks dropped and taken
back, how often the cache was emptied, and how long the translator's
lock was waited for and held, by its holders' kinds. The benchmarks
compare a JDK workload (compiling and running a multi-threaded
application) with the same JDK built for macOS on the same runner
([ROADMAP.md](../ROADMAP.md)).

## Tested runtimes

In CI, each against what Linux prints:

- **Contract tests** (`guests/c/jitlab.c`, `jitstorm.c`, `jitx18.c`,
  `jitcalls.c`, `selfmod.c`, `perverse.c`): calls in and out, indirect
  branches, PC-relative forms, `x18`, system calls, restarts, signals,
  faults resumed at a continuation, a tracer's stops, code patched,
  copied, flushed through either of two views, made executable after it
  was written, given back and written anew, run by many threads while
  another patches it, run on the stack and in a fork child, with the
  memory reading back as written.
- **Programs that treat code as text:** a quine and IOCCC winners.
- **Runtimes:** Node.js 18 (Debian) and 24 (Alpine), OpenJDK 25
  (Alpine; [linux-on-macos.md](linux-on-macos.md#java-and-the-jvm)),
  LuaJIT, Racket, GNU Guile and Python's `eval` (Alpine). Alpine's SBCL
  is linked low and runs in the VM, its code as it is.

## How others do it

Every translator that runs a program's generated code meets the same two
questions: how it learns that code changed, and how its threads share
the code cache.

- **Learning of changes.** Valgrind on arm64 relies on the program's
  `ic ivau` alone, and reports `CTR_EL0` with `IDC` and `DIC` clear, as
  fwe does. QEMU in user mode keeps the pages code came from read-only
  and also takes `ic ivau`, since a JIT that maps its code twice writes
  through a view it does not protect. FEX and Box64 run x86 programs,
  which issue no cache maintenance, so they protect pages and, for pages
  written often, check blocks against their code instead. DynamoRIO on
  AArch64 protects pages too: it runs programs on the host's own
  `CTR_EL0`, and on processors that report `DIC` set, programs
  (HotSpot among them) skip `ic ivau`. Protecting pages costs a fault
  for each write beside code, which a JIT makes all the time; fwe's
  `CTR_EL0` lets it take the program's flushes instead.
- **Sharing the cache.** QEMU, FEX, Box64 and DynamoRIO all build
  translations one at a time, or under a lock per page, and take
  lookups, linking and dropping single blocks off that lock: lookups read
  a table without a lock, a link is one 32-bit write under the target
  block's own lock, and a block's memory is reused only once no thread
  can be in it. fwe's lookups and linked branches take no lock either;
  ways out, linking and drops share its one lock.

How fwe compares with these tools overall is in
[comparisons.md](comparisons.md#translating-or-instrumenting-code).
