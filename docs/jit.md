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
  goes on there. A block is at most 64 instructions and ends at an
  unconditional or indirect branch, at an `isb` and at its page's end; it
  goes on past a conditional branch, whose taken way leaves it, or goes
  to the block's own translation of its target where the block holds it
  (a loop's way back, a skip ahead) with the same registers in place: no
  way out, nor a block of its own made from inside this one.
- **The translation** holds the program's instructions as they are,
  except those whose meaning depends on where they are or that macOS
  does not let a program run unchanged: `adr`, `adrp` and literal loads
  are computed from the program's address; uses of `x18`, system calls,
  thread-pointer accesses and instruction cache flushes are expanded as
  their stubs are, inline; branches out of the block go to translations.
- **Branches.** A direct branch goes through fwe the first time and is
  then linked: straight to its target's translation (a conditional
  branch itself where it reaches, else its way out at the block's end),
  or to code that is not translated (a runtime's helper a JIT calls with
  `bl`) straight there where a branch reaches, otherwise through a veneer
  that loads the target into `x16`, as a linker's veneer does (the
  procedure call standard lets one clobber `x16` and `x17` on a direct
  branch to other code). A `cbz` or `tbz` of `x18` tests the program's
  `x18` inline. A call puts the program's own return address in `x30`,
  so the stack holds only the program's addresses, in words out of line
  that a `bl` goes to (for an indirect call, after its lookup's first
  look), so the block goes on after the `bl` with the code after the
  call. A return looks its address up in a table of returns
  first, and found there goes back to after the call's `bl` with `ret`,
  which the processor predicts from the `bl` as it predicts a native
  return; returns to one of many callers (a tree walk's) would otherwise
  be guessed from the branches before them and missed most times. A call
  is made once: a block that comes to a call another block made already
  branches into that one's words, so a return address has one way back.
  An indirect branch or a return not found among the returns looks its
  target up in a table of translations by program address: one 16-byte load reads an entry's address and translation
  together (single-copy atomic, as the table's writes are), so a match
  leads to the target's own translation. Through `x16` or `x17`, which
  hold the target while it is looked up, the two are read apart, and
  the translation checks that the target is its own (an entry can be
  taken over while such a lookup reads it). An address is looked for in
  the entry its bits pick, then in the other entry of that one's pair,
  so two targets that pick one entry, both run often, do not push each
  other out at every turn. A miss goes through fwe once and fills the
  table. An indirect branch or return into code that is
  not translated (a library's, prepared in place) restores `x16` and
  `x17` and is made through the program's own register, so every
  register is as the program left it: code may count on more than the
  procedure call standard promises (HotSpot calls its atomic stubs
  saying they clobber only `x8`, `x9` and `x30`, and keeps values in
  `x16` across them). One through `x18`, or a call through `x30`, takes
  fwe's trap.
- **`x16` and `x17` stay saved.** A lookup needs two registers, and the
  program owns them all: it saves `x16` and `x17` in two slots of the
  thread's own (reached through `tpidrro_el0`, as `x18`'s is). The
  translation it reaches keeps them there until one of its instructions
  names them or needs fwe's stack (a system call, another expansion),
  and restores them there; a way out or the next lookup saves them again
  only if they were restored. Code that never names them (an
  interpreter's dispatch, calls through pointers, a recursion moving
  `sp` at each call) runs its calls, returns and lookups with no save
  or restore between them. A save, with no register free, puts both below
  `sp` first (without moving it), then each in its slot: six words; a
  restore is four. A block reached by a direct branch with the program's
  own registers is entered past its restore, or where it starts with
  code that runs either way, at a copy of that code made with them in
  place, which joins the rest at the restore. A fault or signal anywhere
  in between is delivered with the program's `x16` and `x17`.
- **`x18` in `x17`.** macOS keeps `x18` for itself, and Linux code uses it
  like any other register (HotSpot's C2 allocates it), so outside
  translations each use of `x18` is a stub that reads and writes the
  program's value in a slot of the thread's (three saves and loads
  around it). Where a translation has `x16` and `x17` saved, `x18` is
  loaded into `x17` once (the slot's address in `x16`), each instruction
  naming it is made to name `x17`, and the value goes back to its slot
  before a branch, a lookup or the restore. A block that uses `x18`
  before anything else loads it at its start, and a way out holding it
  enters such a block past that load: a loop keeping a value in `x18`
  runs as fast as with any other register. A fault or signal there is
  delivered with the program's `x18` taken from `x17`. Where `x16` and
  `x17` are the program's (HotSpot allocates them too), an instruction
  naming `x18` gets one or two scratch registers kept below `sp` without
  moving it, preferring ones the code after it writes before reading:
  no chain of `sp` updates and no wait for a register loaded back, about
  twice as fast as a stub's pushes and pops. A fault or signal inside
  it is delivered as at the instruction, its scratch registers read
  back.
- **Code a translation calls is translated too.** A runtime's helpers in
  its library, the C library, the program's own functions: code fwe
  prepared in place that a translation calls or branches to runs from
  translations as well, read as the program wrote it (each instruction
  fwe rewrote taken from the record of what it was), so what it calls and
  where it returns stay in translations: a C helper's return into a
  JIT's code is a lookup, not a fault. A return is followed only to
  where a translated call returns, or where the code that came into the
  JIT's by a branch fwe could not link returns (below); one to a caller
  that runs as it is (the code that called into the JIT's) goes back
  there. The same code keeps running as it is wherever it is called from
  code that is not translated.
- **Translations of a file's code are kept.** The blocks made from a
  file's code (a runtime's library, the C library, the program's own)
  are kept on disk by the file's identity and the address it is loaded
  at, as prepared code is, and a later process that comes to the same
  code takes them rather than translating it again; this process does
  too, for a block it dropped and needs again. A block is taken only
  where the program's words are as it was made from, and so are the
  calls made in other blocks' words that it goes on into; otherwise it
  is made afresh. Each build of fwe keeps its own. Generated code's
  blocks are made in each process.
- **Calls into translated code.** Native code's call into a JIT's code
  faults the first time; that call site (`blr`) becomes a `bl` to a stub
  in reach that looks the target up as a translation does, and goes to
  its translation, so the next calls fault no more. Code read through
  that site to be translated has its `blr` back. A way in that tells
  nothing of where it came from (a branch through a register, as an
  interpreter's tail call into a JIT's compiled code) has where it
  returns (`x30`) followed instead: the code that came in goes on by
  translation from there, and its next ways in are lookups.
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
  that run it. A block's words are made in two parts (`asm::Asm`): its
  hot words, which run each time it runs, and its cold ones, which run
  only on the way into fwe or out of the common case (a conditional
  branch's way out until it is linked, a return's second look and the
  rest of its lookup, a lookup's miss, a branch to code not translated).
  A chunk is filled a segment at a time (at most 1 MiB, what a
  conditional branch reaches): blocks' hot words from the segment's start
  up and their cold ones from its end down, so the hot words of blocks
  made one after another lie together, each block's cold words in reach
  of its conditional branches. A full chunk is followed by a new one,
  or, when at least half of the cache holds translations dropped since,
  the cache is emptied with every other thread stopped, keeping aside
  the translations a thread may still be in or return into; the code is
  translated again as it runs. A fork child gets its own copy of the
  cache.

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
  made from that cache line (64 bytes) whose words changed, and the code
  is translated again when it next runs. A translation whose words are
  as they were stays: a JIT also flushes lines whose instructions it
  left alone (a word of data beside them changed, code written next to
  them). A translation running when its code is flushed
  goes on to its end: the `isb` that follows a flush ends a block, so
  code that rewrites instructions just ahead of itself runs the new ones.
- **The rest of the memory is the program's.** Nothing else it writes
  costs anything: a JIT's data beside its code, a constant patched, a
  trampoline's target changed.
- **Through any mapping.** A JIT that maps its code twice (a memfd,
  writable and executable) may flush either view, since both are the
  same memory: a flush through either drops the translations made from
  it.
- **Taken back if the same again.** A block a flush dropped is kept
  with the words it was made from; when its address runs again and the
  words are as they were (a method installed again where it was), the
  block is taken back instead of translated anew.
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
  resumes the thread in it. A block is translated with the translator's
  lock let go (`jit::translation`), from one look at the program's words
  (`jit::with_snapshot`), at no address in particular (its expansions'
  starts set, and its branches resolved, where it is placed,
  `jit::place`); with the lock taken
  again it is placed only if the program's words are still as it saw
  them and no other thread placed that block meanwhile, else it is made
  again. A flush landing meanwhile finds nothing to drop, and the check
  sees the change. A new block's direct ways out are linked to
  targets already translated, and ways out waiting for it to it
  (`jit::link_waiting`). The lock is held for microseconds at a time, so
  a thread that finds it held tries again for a few of them
  (`fwe_kernel::shortlock`) before it sleeps on it: sleeping and being
  woken cost the host's scheduler far more than a hold.
- **Ways out:** a block's way out (a direct branch's, or a lookup's
  miss) saves `x16` and `x17` in their slots unless they are saved already
  (`Word::Out`'s `saved`), puts its own address in `x16` and branches to
  its chunk's exit stub (`jit::exit_stub`, the chunk's first words, which
  load the exit gate's address and branch there), so a way out is two
  or three words; the exit gate (`gate::fwe_exit_gate`) saves
  the program's registers in the thread's block, as the system-call gate
  does, and calls `jit::gate_exit` without a signal: the target is
  translated and the branch patched to it (linked, within a chunk) at the
  entry for the way out's state of `x16` and `x17` (`jit::entered`), as
  is the conditional branch the way out is the taken way of, where it
  reaches (`State::link`, undone by `State::unlink`), and the gate enters
  that translation as a lookup does. The blocks the target goes on to
  whatever its conditions (its direct branch's target, a call's and
  where it returns) are made with it, a few deep (`jit::ahead`), and
  linked at once: each would otherwise be a way out of its own as the
  program reached it. The words patched have their
  instruction cache lines invalidated together, with one barrier for all
  (`State::sync_patched`), before the translator's lock is let go, new
  words are written or stopped threads go on: a patch turns one right
  way on into another, while a new block is invalidated as it is
  written, before it is published. Anything else (code
  not translated, a signal to deliver) takes the gate's `brk`, whose
  handler goes on from the block. A way out unlinked again (its target
  dropped, or the cache emptied) has its first word as it was made, into
  the gate again. A lookup that enters the wrong block (one whose entry
  another address took as it read it) goes on at `brk #0x4a54`
  (`jit::EXIT`), which `on_sigtrap` passes to `jit::exit`. A direct branch's target that is code not
  translated is patched to it where a branch reaches and `x16` and `x17`
  are the program's, else to a veneer block (`jit::veneer`: `x16` and
  `x17` restored if saved, then a branch, or the target in `x16` and
  `br x16`). A way out with the guest's `x18` held in `x17`
  (`Word::Out`'s `x18`) is linked past the target's load of it
  (`Block::x18`, `jit::in_x17`, `jit::put_x18`). A `cbz`/`tbz` of `x18`
  loads the guest's `x18` into `x16`
  (saved with `x17` as a lookup saves them) and tests it there.
- **Entries:** a block starts with the check a lookup that read the
  table apart enters at (the target in `x16` against the block's
  address), then its saved entry, where lookups and direct branches with
  `x16` and `x17` saved come in (`Block::body`). `jit::keeps_saved`
  tells which instructions run with them saved; `jit::body_of` restores
  them before any other. Its unsaved entry (`Block::unsaved`) is past
  that restore when the block starts with it, or a copy of the words up
  to it made with them in their registers, which branches into the rest,
  or, at a call or a branch through a register the saved words make with
  them saved, saves them and branches there; where those words name
  `x18`, which the saved words keep in `x17`, a save of `x16` and `x17`
  and a branch into the saved words.
- **The table** of translations by guest address is 2^20 entries of
  (address, translation) at 2^45 (32 TiB, reachable with one `orr`),
  each 16 bytes aligned and written whole (`stp`) for lookups that read
  it whole (`ldp`, single-copy atomic on every Apple processor:
  FEAT_LSE2), its place taken as fwe starts (`jit::configure`), before
  the program maps anything that could take it. An address goes in the
  entry its bits 2 to 21 pick, its earlier holder moving to the other of
  that one's 32-byte pair (`jit::publish`), where a lookup that misses
  the first looks next. A target outside run-time code (a library's)
  gets translation 0; a dropped entry is cleared.
- **The table of returns** at 2^45 + 2^44 is laid out as the table of
  translations: a call's return address and the words after its `bl`
  (`jit::RETS`; the call's words out of line are a `jit::Side`),
  published and dropped with the block that holds the call. A call made in a block's words is noted (`State::calls_made`,
  entered with `x16` and `x17` saved); a block translated later that
  comes to it ends in a way out linked into those words (`Exit::Join`),
  through fwe again if that block is dropped.
- **The code cache's views:** each chunk is mapped twice with
  `mach_vm_remap`, written through the writable view and run from the
  executable one; `jit::in_cache` tells a cache address without a lock.
- **Following:** an exit to code fwe prepared in place
  (`jit::followable`: in an executable mapping of the guest's, not a
  stub) is translated as well, except a return, followed only to the
  return point of a translated call or of an entry by fetch not linked
  to its site (`State::returns`). Such code is read through
  `prepare::original`, which gives back the instruction at a site from
  the sites recorded as stubs were made (`prepare::SITES`), checked
  against the stub's branch back, and a call site's `blr` from those
  linked to call stubs (`prepare::CALL_SITES`).
- **Kept translations:** `jit::kept` keeps a block made from a file's
  code (`kept::keep`) as `jit::translate` made it, before it is placed:
  the program's words it was made from, the calls made in other blocks'
  words in its words' range (`State::calls_made`), its hot and cold
  words with their branches still to resolve (`Asm::fixups`), what each
  word stands for, packed (`Packed::to_bytes`), and its calls. The
  records are files in fwe's private directory, under
  `v<format>-translations/<UUID of fwe's image>-<its thread slots>/<device>-<inode>-<load
  address>/` (the program's own file by its host identity, as the maps
  record names it by none): each process adds the records it made as one
  more file as it ends or replaces its program (a fork child its own
  only), written aside and moved into place, and maps a part's files
  read-only the first time it translates code there; one that finds
  eight merges them into one. `jit::translation` looks for a record of
  a file's code before it translates (`kept::take`), and places a block
  taken (`Asm::restore`) as one just made, the literal of each system
  call's and flush's stub set to where the gate is in this process (fwe's
  image lands elsewhere in each, `kept::relocate`). Other builds' records
  go once they are an hour old.
- **Call sites:** a fetch fault whose `x30` follows a `blr xN` in code
  prepared in place links that site (`jit::link_call_site`): with every
  other thread stopped, a stub doing the table lookup goes in the spare
  page every stub region and loader arena keeps (`prepare::call_stub`),
  and the `blr` becomes a `bl` to it. A thread stopped in such a stub is
  as at the call site, which calls it again (`jit::call_stub_to_guest`):
  a handler running translated code may save its own `x16` and `x17` in
  the slots meanwhile.
- **Guest state:** each translated word records what it stands for
  (`Word`: the guest instruction, with `x16` and `x17` saved or not or
  on their way into their slots, a point inside an expansion before or after its instruction, a lookup, a
  way out; in an exit stub, the way out in `x16`), so `jit::to_guest`
  turns a fault, signal, system call or tracer stop there into the guest's
  state at its instruction: an expansion is undone (`undo`, reading back
  what it pushed) or finished (`finish`, `step`, carrying out its
  remaining words).
- **Flushes:** the `ic ivau` stub (`rewrite::flush_stub`) runs the
  instruction (but through `x18`, whose value only the gate knows, which
  the gate invalidates itself) and calls the gate as a system call's
  stub does. The gate tells the two apart by the stub's load of its
  address (`rewrite::flush_reg`) and calls `jit::flushed`, which drops
  the blocks made from that line whose words changed
  (`jit::drop_lines`): it unpublishes their entries and re-patches the
  branches linked to them into ways out. The other mappings of each file page code was translated from
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
| a call | a `bl`, the return address set, and a branch to the target (after a table lookup for `blr`) | each time |
| a return | a lookup in the table of returns, about seven instructions, and a `ret` the processor predicts; a return the table does not hold looks its target up as an indirect branch does | each time |
| an indirect branch | an inline table lookup, about ten instructions, and a save of `x16` and `x17` where the code before it named them | each time; a miss goes through the exit gate |
| a call from native code into JIT code | a fault | once per call site, then linked; a branch in once, then followed |
| `ic ivau` | a call through the gate | each cache line the program flushes |
| anything else the program writes | nothing | |

`FWE_TIMING=1` prints, as a process exits, what its translations cost:
blocks translated, ways out taken through fwe and the time spent in
them, entries by fetch, cache lines flushed and blocks dropped and taken
back, how often the cache was emptied, and how long the translator's
lock was waited for and held, by its holders' kinds; and the counts that
say which of its work could be skipped (`crates/native/src/jitcount.rs`):
the blocks made from files and from generated code and the time making
each kind, the program's words a block holds and what its words end at
(a branch, a branch through a register, a return, words made already,
the page's end, or the most words a block takes), those made with a second pass of their words for an entry
with the program's own `x16` and `x17` and those entered there,
those made ahead of the program, the blocks taken from those kept and the
time taking them, and the records found for a block's words that the
calls made around it would make otherwise, and of the blocks in use those an
unconditional branch (`b`) leads to: in all, and those nothing else
leads to directly, with their words, by where the branch is (close
behind, within the words a block made at its block's address reads;
elsewhere on their page; on another page). With `FWE_JIT_SEEN=<dir>` each process
adds the blocks it made to that directory (their address and a hash of
their words) and counts those an earlier one made, at the same address
or elsewhere. With `FWE_JIT_COUNT=1` every block counts its runs and
every way back after a call its returns (the words then differ: a
counter at each entry, and every other entry made apart): the report
adds the blocks that ran, those made ahead that ran, the returns into
generated code by the call they come back from, and the pages of
generated code that hold no word a translation changes, with how often
their blocks ran and their lines were flushed. `FWE_JIT_MAP=<dir>`
writes the code cache's map there as a process ends (`jit-<pid>.map`: a
line for each block's hot words and one for its cold ones, each with its
place in the cache, the program address the block was made from, what
each of its words stands for and the words; then how many of the
program's instructions the block was made from and the last of them, or
`cold`), which the benchmarks use to name the samples taken in
translations, with the share in cold words, to show the hottest blocks
word by word, and to count the blocks made by the code they come from,
by what ended them and by their length. The benchmarks
compare a JDK workload (compiling and running a multi-threaded
application), a Node.js script and a Lua script under LuaJIT with the
same releases built for macOS on the same runner
([ROADMAP.md](../ROADMAP.md)), report these counts for each, and run the
same machine code made at run time under fwe and natively (calls and
returns, a switch through `br`, calls through a register, a loop, 4096
functions called in turn, and a function made and run once:
`guests/c/bench.c`'s `jit`).

## Tested runtimes

In CI, each against what Linux prints:

- **Contract tests** (`guests/c/jitlab.c`, `jitstorm.c`, `jitx18.c`,
  `jitcalls.c`, `jitstubsig.c`, `jittail.c`, `selfmod.c`, `perverse.c`):
  calls in and out (with `x16` and `x17` kept through signals whose
  handlers run translated code), branches in through a register (one
  fault, then followed), indirect branches, PC-relative forms, `x18`, system
  calls, restarts, signals,
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
