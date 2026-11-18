# arm64 assembly

The arm64 (AArch64) instruction set as far as fwe's work needs it:
registers, how instructions are encoded, exception levels, the
procedure call standard, branches, loads, stores and atomics, the
memory model and its barriers, system registers, and pointer
authentication and branch targets. It is background, not fwe, as
[linking.md](linking.md) is: how code reaches addresses and which
registers each platform reserves are there; what fwe does with each
instruction is in [linux-on-macos.md](linux-on-macos.md#which-instructions-get-translated-and-how)
and, for code made at run time, in [jit.md](jit.md). The encodings
below are what `clang` assembles and `llvm-objdump -d` prints.

## Registers

| Register | What it is |
|---|---|
| `x0`–`x30` | 31 general registers of 64 bits; `w0`–`w30` are their low 32 bits (writing a `w` register zeroes the top half) |
| `x29` (`fp`) | the frame pointer, by convention |
| `x30` (`lr`) | the link register: `bl` and `blr` put the return address there, `ret` branches to it |
| `sp` | the stack pointer; register number 31 in some instructions |
| `xzr`, `wzr` | the zero register: reads as 0, writes are discarded; register number 31 in the others |
| `pc` | the program counter: not a general register, read only through `adr`, `adrp`, literal loads and the branches that save a return address |
| `v0`–`v31` | 32 SIMD and floating-point registers of 128 bits, named `q`, `d`, `s`, `h`, `b` by the part used |
| `NZCV` | the condition flags, set by `cmp`, `adds`, `tst` and others, read by `b.cond`, `csel` and others |
| `FPCR`, `FPSR` | floating-point control (rounding, flush to zero) and status (exceptions raised) |

Register number 31 means `sp` where an instruction takes a base address
or adds to the stack (`add x0, sp, #16`, `ldr x0, [sp, #8]`) and `xzr`
everywhere else (`orr x0, xzr, x1` is `mov x0, x1`; `subs xzr, x0, x1`
is `cmp x0, x1`). A decoder must know which, instruction by instruction.

## How instructions are encoded

Every instruction is one 32-bit little-endian word, aligned to 4 bytes.
There are no prefixes and no variable lengths, so the instructions of a
range of code are exactly its aligned words: scanning code finds every
instruction, and the only confusion is data that sits among code and
happens to encode one (a literal pool, a jump table).

Register operands sit in fixed fields: `Rd` or `Rt` in bits 4–0, `Rn`
in bits 9–5, `Rm` in bits 20–16 and `Rt2` (a pair's second register) in
bits 14–10. Two words, field by field:

```
8b120020  add x0, x1, x18          Rm = 18 (bits 20-16), Rn = 1, Rd = 0
a9bf7bfd  stp x29, x30, [sp, #-16]!
          opc = 10 (64-bit), bits 24-23 = 11 (pre-index: sp written back first),
          imm7 = -2 (scaled by 8: -16), Rt2 = 30, Rn = 31 (sp), Rt = 29
```

So whether an instruction names `x18` is a matter of reading the fields
its encoding has, not of reading every 5-bit group: an immediate's bits
can look like a register number.

Instructions fwe meets, as encoded:

| Encoding | Instruction | What it does |
|---|---|---|
| `d4000001` | `svc #0` | system call (the immediate is bits 20–5: `svc #0x80` is `d4001001`) |
| `d4200000` | `brk #0` | breakpoint trap (immediate in bits 20–5) |
| `d4000002` | `hvc #0` | call the hypervisor (EL1 only) |
| `00000000` | `udf #0` | permanently undefined: traps as an illegal instruction |
| `d503201f` | `nop` | |
| `d65f03c0` | `ret` | branch to `x30` |
| `14000000`, `94000000` | `b`, `bl` | branch, call: a 26-bit word offset in the low bits |
| `d61f0200`, `d63f0100` | `br x16`, `blr x8` | branch, call through a register |
| `d53bd040`, `d51bd040` | `mrs x0, tpidr_el0`, `msr tpidr_el0, x0` | read, write the thread pointer |
| `d53b0020` | `mrs x0, ctr_el0` | read the cache type |
| `d50b7520` | `ic ivau, x0` | invalidate an instruction cache line |
| `d50b7b20` | `dc cvau, x0` | clean a data cache line |
| `d5033b9f`, `d5033bbf`, `d5033fdf` | `dsb ish`, `dmb ish`, `isb` | barriers |

`mrs`, `msr`, `ic`, `dc` and the barriers are all *system* instructions:
one encoding with fields `op0`, `op1`, `CRn`, `CRm` and `op2` naming the
register or operation (`ic ivau` is `op1` 3, `CRn` 7, `CRm` 5, `op2` 1;
`tpidr_el0` is 3, 3, 13, 0, 2).

## Exception levels

The processor runs at one of four exception levels: EL0 for programs,
EL1 for an operating system's kernel, EL2 for a hypervisor, EL3 for
firmware. An *exception* (a system call, a fault, an interrupt, a trap)
takes the processor up a level and into that level's vector, with the
cause in its `ESR` (exception syndrome register), a faulting address in
`FAR`, and where it happened in `ELR`; `eret` goes back. A program
reaches the level above it with `svc` (EL0 to EL1) and `hvc` (EL1 to
EL2), and traps with `brk` or `udf`. Which system registers and
instructions EL0 may use is the kernel's choice (bits of `SCTLR_EL1`),
which is why Linux and macOS differ on a few of them.

Under Linux and macOS alike, programs run at EL0 and the kernel at EL1;
macOS's kernel also runs Hypervisor.framework's VMs, whose guest kernel
code runs at EL1 under it ([hypervisor.md](hypervisor.md)).

## The procedure call standard

The *Procedure Call Standard for the Arm 64-bit Architecture* (AAPCS64)
is what compiled functions agree on:

| Registers | Role |
|---|---|
| `x0`–`x7` | arguments and results |
| `x8` | the address of a structure result (and, on Linux, a system call's number) |
| `x9`–`x15` | temporaries: the caller saves them if it needs them |
| `x16`, `x17` (`ip0`, `ip1`) | intra-procedure-call scratch: a linker's veneer or PLT stub may change them between a call and its target |
| `x18` | the platform register ([linking.md](linking.md#registers-the-platform-reserves)) |
| `x19`–`x28` | kept by the callee |
| `x29`, `x30` | frame pointer and link register, saved by a function that calls others |
| `sp` | 16-byte aligned at every call; Linux has no red zone below it |
| `v0`–`v7` | floating-point and SIMD arguments and results |
| `v8`–`v15` | their low 64 bits kept by the callee |

A function's frame usually starts and ends:

```
stp  x29, x30, [sp, #-32]!   // save fp and lr, make the frame
mov  x29, sp
...
ldp  x29, x30, [sp], #32     // restore them, drop the frame
ret
```

The standard binds only calls between functions. Code the compiler or a
JIT writes for itself may keep anything anywhere: HotSpot calls its own
atomic stubs saying they change only `x8`, `x9` and `x30`, so the caller
keeps other temporaries live across the call.

## Linux and macOS: two variants of the standard

Linux follows AAPCS64 as Arm publishes it. Apple's platforms follow it
with changes of their own (Apple's *Writing ARM64 code for Apple
platforms*), and the C types differ too. Code built for one is not
callable from the other without care, which is one reason fwe never
lets Linux code call macOS libraries directly:

| | Linux (AAPCS64) | macOS (Apple arm64) |
|---|---|---|
| `x18` | a temporary like `x9`–`x15` | reserved: never used, and changed by the kernel at will |
| `x29` | a frame pointer by convention; may be omitted (`-fomit-frame-pointer`) | must always point at a valid frame record |
| Below `sp` | nothing: a signal frame may be written there at any moment | a 128-byte red zone a function may use without moving `sp` |
| Variadic arguments (`printf`'s) | passed as the others are: registers first, then the stack | always on the stack, 8 bytes each |
| `va_list` | a structure: the next stack argument and the unread register areas | a pointer into the stack |
| Arguments on the stack | each in a slot of 8 bytes | packed at their own alignment (two `char`s share two bytes) |
| `char` or `short` arguments and results | the callee extends them; the bits above are undefined | the caller extends them to 32 bits |
| `char` | unsigned | signed |
| `long double` | 128-bit IEEE quadruple precision, in software | the same as `double` |
| `wchar_t` | 32-bit, unsigned | 32-bit, signed |
| Symbol names | as written (`main`) | with a leading underscore (`_main`) |
| Thread pointer | `TPIDR_EL0`, the program's | `TPIDRRO_EL0`, the kernel's; `TPIDR_EL0` not kept |
| Thread-local storage | at offsets from the thread pointer (or through TLS descriptors) | through a descriptor, by a call (`tlv_get_addr`) |
| Pointer authentication | return addresses signed where built for it (`-mbranch-protection`) | throughout Apple's own `arm64e` binaries; third-party code is plain `arm64` |
| System calls | `svc #0`, number in `x8`, error as `-errno` in `x0` | `svc #0x80`, number in `x16`, error as the carry flag and `errno` in `x0` |
| A signal handler's frame | Linux's `ucontext_t`, with `sigcontext` and its records (FP and SIMD, ESR) | macOS's `ucontext_t`, pointing to a separate `mcontext` |

Where these meet fwe:

- **`x18` and the thread pointer** are why guest code is rewritten
  natively ([linux-on-macos.md](linux-on-macos.md#registers-and-the-thread-pointer)).
- **No red zone** on Linux is what lets fwe's stubs save registers just
  below a Linux program's `sp`: the program keeps nothing there. A
  signal arriving in a stub would write its frame there too, so it is
  delivered as if at the stub's site, the registers it saved taken back
  ([linux-on-macos.md](linux-on-macos.md#x18-a-stub-per-use)).
- **System calls and signal frames** are fwe's to convert
  ([linux-on-macos.md](linux-on-macos.md#system-call-entry),
  [Dispositions, masks and frames](linux-on-macos.md#dispositions-masks-and-frames)).
- **The argument rules and types** keep a Linux program and a macOS
  library apart: a call between them would pass variadic arguments,
  small integers and `long double` differently. A Linux program only
  ever calls Linux code: its own libraries, inside its root.
- **Linking and thread-local storage** are compared in
  [linking.md](linking.md#thread-local-storage).

## Branches and reach

A direct branch's target is an offset from the branch, in words:

| Instruction | Reach |
|---|---|
| `b`, `bl` | ±128 MiB |
| `b.cond`, `cbz`, `cbnz` | ±1 MiB |
| `tbz`, `tbnz` (test one bit) | ±32 KiB |
| `br`, `blr`, `ret` (through a register) | anywhere |

Code that must reach further goes through a register: a linker inserts a
*veneer* (`adrp x16, target; add x16, x16, :lo12:target; br x16`),
which is why `x16` and `x17` are the standard's scratch registers. How
code reaches data addresses (`adr`, `adrp`, literal loads, `movz` and
`movk`) is in [linking.md](linking.md#relocations-and-how-arm64-code-reaches-addresses).

## Loads, stores and atomics

Only loads and stores touch memory; everything else works on registers.
The addressing forms:

| Form | Example | Address, and what changes |
|---|---|---|
| unsigned offset | `ldr x0, [x1, #8]` | `x1 + 8` (the offset scaled by the size) |
| unscaled | `ldur x0, [x1, #-3]` | `x1 - 3` |
| pre-index | `ldr x0, [x1, #8]!` | `x1 + 8`, then `x1` set to it |
| post-index | `ldr x0, [x1], #8` | `x1`, then `x1` set to `x1 + 8` |
| register offset | `ldr x0, [x1, x2, lsl #3]` | `x1 + x2 * 8` |
| pair | `ldp x0, x1, [sp, #16]` | two registers, adjacent |
| literal | `ldr x0, label` | `pc` + offset (±1 MiB) |

Each has its store (`str`, `stur`, `stp`) and its sizes (`ldrb`,
`ldrh`, `ldrsw`...). Multi-threaded code adds:

- **Exclusives:** `ldxr` reads and marks the address, `stxr` stores only
  if nothing else wrote it since, and says whether it did; a loop of the
  two makes any atomic operation. `ldaxr` and `stlxr` add ordering.
- **Acquire and release:** `ldar` (no later access moves before it) and
  `stlr` (no earlier access moves after it), the building blocks of
  locks.
- **Large System Extensions** (LSE, Armv8.1): single instructions for
  compare-and-swap (`cas`, `casp` for a pair), swap (`swp`) and
  arithmetic (`ldadd`, `ldset`, `ldclr`...) on memory, each with
  acquire and release forms. Apple's processors have them.

## The memory model and barriers

arm64 is weakly ordered: a core's loads and stores may be seen by other
cores in another order than the program's, except where the program
orders them: acquire and release accesses, address and data
dependencies, and barriers:

- **`dmb`** (data memory barrier): accesses before it are seen before
  accesses after it. `dmb ish` covers the inner shareable domain, every
  core that runs the program's threads.
- **`dsb`** (data synchronization barrier): stronger: nothing after it
  runs until the accesses and cache maintenance before it are complete.
- **`isb`** (instruction synchronization barrier): this core drops the
  instructions it has already fetched and fetches again; needed after
  changing code, or a system register that changes how code runs.

Writing code and running it takes the cache maintenance described in
[jit.md](jit.md#why-a-program-flushes-the-instruction-cache): `dc cvau`,
`ic ivau` and these barriers.

## System registers a program reads

| Register | Holds | EL0 under Linux | EL0 under macOS |
|---|---|---|---|
| `TPIDR_EL0` | the thread pointer (thread-local storage) | read and write | not kept for programs: macOS uses `TPIDRRO_EL0` |
| `TPIDRRO_EL0` | a thread pointer the program may only read | read | read: the thread's data (TSD) |
| `CTR_EL0` | cache line sizes, and whether cache maintenance can be skipped (`IDC`, `DIC`) | read | traps |
| `DCZID_EL0` | the block size `dc zva` zeroes | read | read |
| `CNTVCT_EL0`, `CNTFRQ_EL0` | the virtual counter and its frequency | read | read |
| `MIDR_EL1` and the ID registers | the processor's model and features | read, emulated by the kernel | not readable: `sysctl` instead |

What fwe does with each is in
[linux-on-macos.md](linux-on-macos.md#registers-and-the-thread-pointer).

## Pointer authentication and branch targets

- **Pointer authentication** (PAC, Armv8.3) puts a signature in a
  pointer's unused top bits, made from the pointer, a key the kernel
  keeps, and a modifier such as `sp`. `paciasp` (`d503233f`) signs `x30`
  as a function starts, `autiasp` (`d50323bf`) checks it before `ret`,
  and a pointer whose check fails faults when used. Both are in the
  *hint* space, so a processor or kernel without PAC runs them as `nop`.
  `blraa`, `retaa` and the other combined forms are not hints.
- **Branch target identification** (BTI, Armv8.5) marks the places an
  indirect branch may land: `bti c` (`d503245f`) for calls, `bti j` for
  jumps; on a page mapped *guarded*, an indirect branch to anything else
  traps. `paciasp` counts as a landing pad for calls. `bti` is a hint
  too.

Linux programs built with `-mbranch-protection=standard` use both; how
each kernel and fwe treat them is in
[linux-on-macos.md](linux-on-macos.md#cache-maintenance-pac-and-bti).

## Reading code

- `llvm-objdump -d file` (or `objdump -d` from binutils, on Linux)
  disassembles a file; `--no-show-raw-insn` drops the encodings.
- `clang -c -arch arm64 x.s` assembles on a Mac; `llvm-mc
  --show-encoding` prints the encoding of each instruction it reads.
- Arm's *Architecture Reference Manual for A-profile* (the "Arm ARM")
  is the definition of every instruction and register, and its
  *Procedure Call Standard* (AAPCS64) is published with the ABI
  documents on GitHub (`ARM-software/abi-aa`).
